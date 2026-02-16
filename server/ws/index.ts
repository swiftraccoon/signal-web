import { WebSocketServer, WebSocket as WsWebSocket } from 'ws';
import http from 'http';
import config from '../config';
import { addConnection, removeConnection, getConnection, isOnline } from './connections';
import { handleMessage } from './handler';
import { consumeWsTicket } from './tickets';
import { MAX_WS_MESSAGE_SIZE, WS_MSG_TYPE } from '../../shared/constants';
import logger from '../logger';
import { audit } from '../audit';
import { incr } from '../metrics';
import { stmt, getConversationPartners } from '../db';
import { getRedis } from '../redis';
import type { DbUser, UserRateLimitEntry, WsUser } from '../../shared/types';

// Extend WebSocket with custom properties
interface SignalWebSocket extends WsWebSocket {
  _isAlive: boolean;
  _userId: number;
}

const WS_RATE_WINDOW = 1000;
const PING_INTERVAL = 30000;

// Per-message-type rate limits (max messages per second)
const WS_RATE_LIMITS: Record<string, number> = {
  [WS_MSG_TYPE.MESSAGE]: 20,
  [WS_MSG_TYPE.TYPING]: 3,
  [WS_MSG_TYPE.READ_RECEIPT]: 10,
  [WS_MSG_TYPE.DISAPPEARING_TIMER]: 5,
  [WS_MSG_TYPE.ACK]: 50,
};
const WS_RATE_LIMIT_DEFAULT = 20;

// C3: Per-userId, per-type rate limiting — persists across reconnections (NOT deleted on disconnect)
// Key format: "userId:msgType"
const userRateLimits = new Map<string, UserRateLimitEntry>();

// C3: Periodic cleanup of stale rate limit entries (replaces on-disconnect deletion)
setInterval(() => {
  const now = Date.now();
  for (const [key, limit] of userRateLimits) {
    if (now - limit.windowStart > WS_RATE_WINDOW * 10) {
      userRateLimits.delete(key);
    }
  }
}, WS_RATE_WINDOW * 10);

// Redis-backed rate limiting with in-memory fallback (per message type)
async function checkWsRateLimit(userId: number, msgType: string): Promise<boolean> {
  const maxCount = WS_RATE_LIMITS[msgType] ?? WS_RATE_LIMIT_DEFAULT;
  const redis = getRedis();
  if (redis) {
    try {
      const key = `wsrl:${userId}:${msgType}`;
      const count = await redis.incr(key);
      if (count === 1) {
        await redis.pexpire(key, WS_RATE_WINDOW);
      }
      return count <= maxCount;
    } catch (err) {
      logger.warn({ err, userId, msgType }, 'Redis rate limit check failed, falling back to in-memory');
      // Fall through to in-memory logic
    }
  }

  // In-memory fallback
  const bucketKey = `${userId}:${msgType}`;
  const now = Date.now();
  let limit = userRateLimits.get(bucketKey);
  if (!limit || now - limit.windowStart > WS_RATE_WINDOW) {
    limit = { count: 0, windowStart: now };
    userRateLimits.set(bucketKey, limit);
  }
  limit.count++;
  return limit.count <= maxCount;
}

function setupWebSocket(server: http.Server): WebSocketServer {
  const wss = new WebSocketServer({
    server,
    maxPayload: MAX_WS_MESSAGE_SIZE,
  });

  // Ping/pong keepalive - detect stale connections
  const pingInterval = setInterval(() => {
    for (const client of wss.clients) {
      const ws = client as SignalWebSocket;
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

  wss.on('connection', (rawWs: WsWebSocket, req: http.IncomingMessage) => {
    const ws = rawWs as SignalWebSocket;

    // C7: Origin validation via explicit allowlist (not trusting Host header)
    const origin = req.headers.origin;
    if (config.IS_PRODUCTION && !origin) {
      logger.warn({ ip: req.socket.remoteAddress }, 'WS rejected: missing Origin header');
      audit('ws_rejected', { ip: req.socket.remoteAddress as string, details: 'Missing Origin' });
      ws.close(4003, 'Origin required');
      return;
    }
    if (origin) {
      if (config.ALLOWED_WS_ORIGINS.length > 0) {
        if (!config.ALLOWED_WS_ORIGINS.includes(origin)) {
          ws.close(4003, 'Invalid origin');
          return;
        }
      } else if (config.IS_PRODUCTION) {
        // No origins configured in production — reject all cross-origin
        ws.close(4003, 'Invalid origin');
        return;
      }
      // In development with no explicit config, allow all (dev convenience)
    }

    const params = new URL(req.url || '', 'http://localhost').searchParams;
    const ticket = params.get('ticket');

    if (!ticket) {
      ws.close(4001, 'Authentication required');
      return;
    }

    const ticketData = consumeWsTicket(ticket);
    if (!ticketData) {
      ws.close(4001, 'Invalid or expired ticket');
      return;
    }
    const user: WsUser = { id: ticketData.userId, username: ticketData.username };

    // Verify user still exists in database AND userId matches (prevents stale ticket
    // from authenticating as wrong user if account was deleted and re-created)
    const dbUser = stmt.getUserByUsername.get(user.username) as DbUser | undefined;
    if (!dbUser || dbUser.id !== user.id) {
      ws.close(4001, 'User not found');
      return;
    }

    // H1: Reject WS connection if password was changed after ticket was issued
    if (dbUser.password_changed_at) {
      const changedAt = new Date(dbUser.password_changed_at + 'Z').getTime();
      // Ticket was issued at (expiresAt - TTL), check if password changed after that
      const ticketIssuedAt = ticketData.expiresAt - 30000; // WS_TICKET_TTL_MS is 30s
      if (ticketIssuedAt < changedAt) {
        ws.close(4001, 'Session invalidated');
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

    // Send this user only their contacts' online status FIRST
    const partnerIds = getConversationPartners(user.id);
    const onlinePartnerIds = partnerIds.filter(id => isOnline(id));
    ws.send(JSON.stringify({
      type: WS_MSG_TYPE.PRESENCE,
      onlineUserIds: onlinePartnerIds,
    }));

    // THEN broadcast presence to partners (so they know you're online)
    broadcastPresence(user.id, user.username, true);

    // Check signed pre-key freshness
    const signedPreKey = stmt.getSignedPreKey.get(user.id) as { uploaded_at?: number } | undefined;
    if (signedPreKey?.uploaded_at) {
      const ageSec = Math.floor(Date.now() / 1000) - signedPreKey.uploaded_at;
      if (ageSec > 14 * 24 * 3600) { // > 14 days
        ws.send(JSON.stringify({
          type: WS_MSG_TYPE.PREKEY_STALE,
          signedPreKeyAge: ageSec,
        }));
      }
    }

    // C3: Per-userId, per-type rate limiting (persists across reconnections, Redis-backed with fallback)
    ws.on('message', async (data: Buffer | ArrayBuffer | Buffer[]) => {
      incr('wsMessagesIn');

      // Parse JSON before rate limiting so we can apply per-type limits
      let msg: Record<string, unknown>;
      try {
        msg = JSON.parse(data.toString()) as Record<string, unknown>;
      } catch {
        ws.send(JSON.stringify({ type: WS_MSG_TYPE.ERROR, message: 'Invalid JSON' }));
        return;
      }

      // Normalize unknown types to a single sentinel key to prevent unbounded Map growth
      const msgType = typeof msg.type === 'string' ? msg.type : '';
      const rateLimitType = msgType in WS_RATE_LIMITS ? msgType : '__unknown__';
      const withinLimit = await checkWsRateLimit(user.id, rateLimitType);
      if (!withinLimit) {
        ws.send(JSON.stringify({ type: WS_MSG_TYPE.ERROR, message: 'Rate limit exceeded' }));
        return;
      }
      await handleMessage(ws, user, msg);
    });

    ws.on('close', () => {
      removeConnection(user.id, ws);
      // C3: Do NOT delete rate limit state on disconnect — let it expire via periodic cleanup
      logger.debug({ userId: user.id, username: user.username }, 'WS disconnected');
      broadcastPresence(user.id, user.username, false);
    });

    ws.on('error', (err: Error) => {
      logger.error({ err, userId: user.id }, 'WS error');
      removeConnection(user.id, ws);
    });
  });

  return wss;
}

// Broadcast presence only to users who have exchanged messages with this user
function broadcastPresence(userId: number, username: string, online: boolean): void {
  const partnerIds = getConversationPartners(userId);

  for (const partnerId of partnerIds) {
    if (isOnline(partnerId)) {
      const partnerWs = getConnection(partnerId);
      if (partnerWs && partnerWs.readyState === WsWebSocket.OPEN) {
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

export { setupWebSocket };
