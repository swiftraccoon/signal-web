import http from 'http';
import express, { Request, Response, NextFunction } from 'express';
import path from 'path';
import helmet from 'helmet';
import compression from 'compression';
import config from './config';
import logger from './logger';
import { stmt, db, audit } from './db';
import { generalLimiter } from './middleware/rateLimiter';
import { setupWebSocket } from './ws';
import { incr, trackRequestDuration, getSnapshot } from './metrics';
import authRouter from './routes/auth';
import keysRouter from './routes/keys';
import usersRouter from './routes/users';
import messagesRouter from './routes/messages';

const app = express();

// M12: Disable X-Powered-By header (leaks framework info)
app.disable('x-powered-by');

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
        ? ["'self'", "wss:"]
        : ["'self'", "ws://localhost:*", "wss://localhost:*"],
      imgSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"],
      baseUri: ["'self'"],
      formAction: ["'self'"],
    },
  },
  // L12: Enable COEP with credentialless (less restrictive than require-corp but still provides isolation)
  crossOriginEmbedderPolicy: { policy: 'credentialless' as 'require-corp' },
  crossOriginOpenerPolicy: { policy: 'same-origin' },
  crossOriginResourcePolicy: { policy: 'same-origin' },
  referrerPolicy: { policy: 'no-referrer' },
  // L4: Enable HSTS with preload in production
  hsts: config.IS_PRODUCTION ? { maxAge: 63072000, includeSubDomains: true, preload: true } : false,
}));

app.use(express.json({ limit: '64kb' }));

// H6: Reject non-JSON Content-Type on API mutation endpoints
app.use('/api', (req: Request, res: Response, next: NextFunction) => {
  if (req.method !== 'GET' && req.method !== 'HEAD' && req.method !== 'OPTIONS') {
    const ct = req.get('Content-Type');
    if (!ct || !ct.startsWith('application/json')) {
      res.status(415).json({ error: 'Content-Type must be application/json' });
      return;
    }
  }
  next();
});

// Request logging and timing middleware
app.use((req: Request, res: Response, next: NextFunction) => {
  const start = performance.now();
  incr('httpRequests');

  res.on('finish', () => {
    const duration = Math.round(performance.now() - start);
    const logData: Record<string, unknown> = {
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
    trackRequestDuration(req.method, normalizedPath!, duration);

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
app.get('/health', (_req: Request, res: Response) => {
  let dbOk = false;
  try {
    db.prepare('SELECT 1').get();
    dbOk = true;
  } catch { /* db unavailable */ }
  const status = dbOk ? 'ok' : 'degraded';
  res.status(dbOk ? 200 : 503).json({ status });
});

// M7: Metrics endpoint — use socket remoteAddress for localhost check (ignores X-Forwarded-For)
app.get('/metrics', (req: Request, res: Response, next: NextFunction) => {
  if (config.IS_PRODUCTION) {
    const rawIp = req.socket.remoteAddress || '';
    const isLocalhost = rawIp === '127.0.0.1' || rawIp === '::1' || rawIp === '::ffff:127.0.0.1';
    if (!isLocalhost) {
      res.status(403).json({ error: 'Forbidden' });
      return;
    }
  }
  next();
}, (_req: Request, res: Response) => {
  res.json(getSnapshot());
});

// Serve client static files - resolve from compiled output location
const clientDir = path.join(__dirname, '..', '..', 'client');
app.use(express.static(clientDir, {
  index: 'index.html',
  dotfiles: 'ignore',
}));

// API routes
app.use('/api/auth', authRouter);
app.use('/api/keys', keysRouter);
app.use('/api/users', usersRouter);
app.use('/api/messages', messagesRouter);

// Catch-all: return JSON 404 for API routes, index.html for SPA routes
app.use((req: Request, res: Response) => {
  if (req.path.startsWith('/api/')) {
    res.status(404).json({ error: 'Not found' });
  } else {
    res.sendFile(path.join(clientDir, 'index.html'));
  }
});

// C6: Global error handler — prevents stack trace leakage
app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
  logger.error({ err: err.message }, 'Unhandled error');
  res.status(500).json({ error: 'Internal server error' });
});

const server = http.createServer(app);
const wss = setupWebSocket(server);

// Purge delivered messages every hour
const purgeInterval = setInterval(() => {
  try {
    stmt.purgeDelivered.run();
    stmt.purgeStale.run();
    stmt.purgeExpiredRefreshTokens.run();
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
function shutdown(signal: string): void {
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
