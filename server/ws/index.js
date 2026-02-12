const { WebSocketServer } = require('ws');
const jwt = require('jsonwebtoken');
const url = require('url');
const config = require('../config');
const { addConnection, removeConnection, getConnection, isOnline, broadcastToAll, getAllOnlineUserIds } = require('./connections');
const { handleMessage } = require('./handler');
const { MAX_WS_MESSAGE_SIZE, WS_MSG_TYPE } = require('../../shared/constants');
const logger = require('../logger');
const { incr } = require('../metrics');
const { audit, stmt } = require('../db');

const WS_RATE_LIMIT = 20;
const WS_RATE_WINDOW = 1000;
const PING_INTERVAL = 30000;
const PONG_TIMEOUT = 10000;

// Per-userId rate limiting (persists across reconnections)
const userRateLimits = new Map(); // userId -> { count, windowStart }

function setupWebSocket(server) {
  const wss = new WebSocketServer({
    server,
    maxPayload: MAX_WS_MESSAGE_SIZE,
  });

  // Ping/pong keepalive - detect stale connections
  const pingInterval = setInterval(() => {
    for (const ws of wss.clients) {
      if (ws._isAlive === false) {
        logger.debug({ userId: ws._userId }, 'Terminating stale WS connection (no pong)');
        ws.terminate();
        continue;
      }
      ws._isAlive = false;
      ws.ping();
    }
  }, PING_INTERVAL);

  wss.on('close', () => {
    clearInterval(pingInterval);
  });

  wss.on('connection', (ws, req) => {
    // Origin validation
    const origin = req.headers.origin;
    if (origin) {
      try {
        const originUrl = new URL(origin);
        const expectedHost = req.headers.host;
        // Strict host comparison (prevents localhost.evil.com bypass)
        if (originUrl.host !== expectedHost) {
          // Allow localhost variants in development
          const isLocalDev = !config.IS_PRODUCTION && (
            originUrl.hostname === 'localhost' || originUrl.hostname === '127.0.0.1'
          );
          if (!isLocalDev) {
            ws.close(4003, 'Invalid origin');
            return;
          }
        }
      } catch {
        ws.close(4003, 'Invalid origin');
        return;
      }
    }

    const params = new url.URL(req.url, 'http://localhost').searchParams;
    const ticket = params.get('ticket');
    const token = params.get('token');

    let user;

    // Prefer ticket-based auth (short-lived, one-time)
    if (ticket) {
      let consumeWsTicket;
      try {
        consumeWsTicket = require('../routes/auth').consumeWsTicket;
      } catch {
        ws.close(4001, 'Auth system unavailable');
        return;
      }
      const ticketData = consumeWsTicket(ticket);
      if (!ticketData) {
        ws.close(4001, 'Invalid or expired ticket');
        return;
      }
      user = { id: ticketData.userId, username: ticketData.username };
    } else if (token) {
      // Fallback to JWT (for backward compat / tests)
      try {
        user = jwt.verify(token, config.JWT_SECRET, {
          algorithms: [config.JWT_ALGORITHM],
        });
      } catch {
        ws.close(4001, 'Invalid token');
        return;
      }
    } else {
      ws.close(4001, 'Authentication required');
      return;
    }

    // Check if password was changed after token was issued (session invalidation)
    const dbUser = stmt.getUserByUsername.get(user.username);
    if (!dbUser) {
      ws.close(4001, 'User not found');
      return;
    }
    if (dbUser.password_changed_at && user.iat) {
      const changedAt = Math.floor(new Date(dbUser.password_changed_at + 'Z').getTime() / 1000);
      if (user.iat < changedAt) {
        ws.close(4001, 'Token invalidated by password change');
        return;
      }
    }

    ws._isAlive = true;
    ws._userId = user.id;

    ws.on('pong', () => {
      ws._isAlive = true;
    });

    addConnection(user.id, ws);
    incr('wsConnections');

    logger.debug({ userId: user.id, username: user.username }, 'WS connected');

    // Broadcast presence only to users who have exchanged messages with this user
    broadcastPresence(user.id, user.username, true);

    // Send this user the list of currently online users (filtered to contacts)
    const onlineIds = getAllOnlineUserIds();
    ws.send(JSON.stringify({
      type: WS_MSG_TYPE.PRESENCE,
      onlineUserIds: onlineIds,
    }));

    // Per-userId rate limiting (persists across reconnections)
    ws.on('message', (data) => {
      incr('wsMessagesIn');
      const now = Date.now();
      let limit = userRateLimits.get(user.id);
      if (!limit || now - limit.windowStart > WS_RATE_WINDOW) {
        limit = { count: 0, windowStart: now };
        userRateLimits.set(user.id, limit);
      }
      limit.count++;
      if (limit.count > WS_RATE_LIMIT) {
        ws.send(JSON.stringify({ type: 'error', message: 'Rate limit exceeded' }));
        return;
      }
      handleMessage(ws, user, data.toString());
    });

    ws.on('close', () => {
      removeConnection(user.id, ws);
      logger.debug({ userId: user.id, username: user.username }, 'WS disconnected');
      broadcastPresence(user.id, user.username, false);
    });

    ws.on('error', (err) => {
      logger.error({ err, userId: user.id }, 'WS error');
      removeConnection(user.id, ws);
    });
  });

  return wss;
}

// Broadcast presence only to users who have exchanged messages with this user
function broadcastPresence(userId, username, online) {
  // Get conversation partners - users who have sent or received messages with this user
  const { getConversationPartners } = require('../db');
  const partnerIds = getConversationPartners(userId);

  for (const partnerId of partnerIds) {
    if (isOnline(partnerId)) {
      const partnerWs = getConnection(partnerId);
      if (partnerWs && partnerWs.readyState === 1) {
        partnerWs.send(JSON.stringify({
          type: WS_MSG_TYPE.PRESENCE,
          userId,
          username,
          online,
        }));
      }
    }
  }
}

module.exports = { setupWebSocket };
