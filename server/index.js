const http = require('http');
const express = require('express');
const path = require('path');
const helmet = require('helmet');
const compression = require('compression');
const config = require('./config');
const logger = require('./logger');
const { stmt, db, audit } = require('./db');
const { generalLimiter } = require('./middleware/rateLimiter');
const { authenticateToken } = require('./middleware/auth');
const { setupWebSocket } = require('./ws');
const { incr, trackRequestDuration, getSnapshot } = require('./metrics');

const app = express();

// Trust proxy in production (for correct client IP behind load balancers)
if (config.IS_PRODUCTION) {
  app.set('trust proxy', 1);
}

// Compression for all HTTP responses
app.use(compression());

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'"],
      connectSrc: config.IS_PRODUCTION
        ? ["'self'"]  // 'self' covers wss: on same origin in production
        : ["'self'", "ws://localhost:*"],
      imgSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"],
      baseUri: ["'self'"],
      formAction: ["'self'"],
    },
  },
  crossOriginEmbedderPolicy: false, // require-corp blocks same-origin static assets without CORP headers
  crossOriginOpenerPolicy: { policy: 'same-origin' },
  crossOriginResourcePolicy: { policy: 'same-origin' },
  referrerPolicy: { policy: 'no-referrer' },
  // Only enable HSTS in production (breaks http://localhost in dev)
  hsts: config.IS_PRODUCTION ? { maxAge: 31536000, includeSubDomains: true } : false,
}));

app.use(express.json({ limit: '64kb' }));

// Request logging and timing middleware
app.use((req, res, next) => {
  const start = performance.now();
  incr('httpRequests');

  res.on('finish', () => {
    const duration = Math.round(performance.now() - start);
    const logData = {
      method: req.method,
      url: req.originalUrl,
      status: res.statusCode,
      durationMs: duration,
      ip: req.ip,
    };

    if (req.user) logData.userId = req.user.id;

    // Track for metrics
    // Normalize path (replace numeric IDs with :id)
    const normalizedPath = req.route
      ? req.baseUrl + req.route.path
      : req.originalUrl.split('?')[0];
    trackRequestDuration(req.method, normalizedPath, duration);

    if (res.statusCode >= 500) {
      incr('httpErrors');
      logger.error(logData, 'Request error');
    } else if (res.statusCode >= 400) {
      logger.warn(logData, 'Request client error');
    } else {
      logger.info(logData, 'Request');
    }
  });

  next();
});

app.use(generalLimiter);

// Health check - no auth, no rate limit
app.get('/health', (req, res) => {
  let dbOk = false;
  try {
    db.prepare('SELECT 1').get();
    dbOk = true;
  } catch {}
  const status = dbOk ? 'ok' : 'degraded';
  res.status(dbOk ? 200 : 503).json({ status });
});

// Metrics endpoint - protected, localhost-only in production
app.get('/metrics', (req, res, next) => {
  if (config.IS_PRODUCTION) {
    const ip = req.ip || req.socket.remoteAddress;
    if (ip !== '127.0.0.1' && ip !== '::1' && ip !== '::ffff:127.0.0.1') {
      return res.status(403).json({ error: 'Forbidden' });
    }
  }
  next();
}, (req, res) => {
  res.json(getSnapshot());
});

app.use(express.static(path.join(__dirname, '..', 'client'), {
  index: 'index.html',
  dotfiles: 'ignore',
}));

// API routes
app.use('/api/auth', require('./routes/auth'));
app.use('/api/keys', require('./routes/keys'));
app.use('/api/users', require('./routes/users'));
app.use('/api/messages', require('./routes/messages'));

const server = http.createServer(app);
const wss = setupWebSocket(server);

// Purge delivered messages every hour
const purgeInterval = setInterval(() => {
  try {
    stmt.purgeDelivered.run();
    stmt.purgeStale.run();
    logger.info('Message purge completed');
  } catch (err) {
    logger.error({ err }, 'Purge error');
  }
}, 60 * 60 * 1000);

// Log metrics snapshot every 5 minutes
const metricsInterval = setInterval(() => {
  const snap = getSnapshot();
  logger.info({
    wsConnections: snap.wsConnections,
    wsMessagesIn: snap.wsMessagesIn,
    wsMessagesOut: snap.wsMessagesOut,
    httpRequests: snap.httpRequests,
    httpErrors: snap.httpErrors,
    dbQueries: snap.dbQueries,
    dbSlowQueries: snap.dbSlowQueries,
    uptimeSec: snap.uptimeSec,
  }, 'Metrics snapshot');
}, 5 * 60 * 1000);

// Graceful shutdown
function shutdown(signal) {
  logger.info({ signal }, 'Shutdown signal received, closing gracefully...');
  audit('server_shutdown', { details: signal });

  clearInterval(purgeInterval);
  clearInterval(metricsInterval);

  // Close WebSocket server - sends close frames to all clients
  wss.close(() => {
    logger.info('WebSocket server closed');
  });

  // Stop accepting new HTTP connections
  server.close(() => {
    logger.info('HTTP server closed');

    // Close SQLite
    try {
      db.close();
      logger.info('Database closed');
    } catch (err) {
      logger.error({ err }, 'Error closing database');
    }

    process.exit(0);
  });

  // Force exit after 10 seconds if graceful shutdown hangs
  setTimeout(() => {
    logger.error('Forced shutdown after timeout');
    process.exit(1);
  }, 10000).unref();
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

const HOST = process.env.HOST || '0.0.0.0';
server.listen(config.PORT, HOST, () => {
  logger.info({ port: config.PORT, host: HOST }, 'Signal-Web server running');
  audit('server_started', { details: `${HOST}:${config.PORT}` });
});
