import WebSocket from 'ws';
import { getConnection, isOnline } from './connections';
import { stmt } from '../db';
import { WS_MSG_TYPE } from '../../shared/constants';
import { incr } from '../metrics';
import logger from '../logger';
import { getRedis } from '../redis';
import type { WsUser, DbUser, DbMarkDeliveredResult } from '../../shared/types';

const MAX_MESSAGE_BODY_SIZE = 50 * 1024; // 50KB explicit body limit

// C4: Message replay prevention — track recent message IDs per sender (TTL-based)
const recentMessageIds = new Map<string, number>(); // "senderId:msgId" -> timestamp
const MESSAGE_ID_TTL_MS = 60000; // 60 seconds
setInterval(() => {
  const now = Date.now();
  for (const [key, ts] of recentMessageIds) {
    if (now - ts > MESSAGE_ID_TTL_MS) recentMessageIds.delete(key);
  }
}, 30000);

// Redis-backed replay detection with in-memory fallback
// Returns true if message is NEW (not a replay), false if it IS a replay
async function checkReplay(dedupeKey: string): Promise<boolean> {
  const redis = getRedis();
  if (redis) {
    try {
      const result = await redis.set(dedupeKey, '1', 'PX', MESSAGE_ID_TTL_MS, 'NX');
      return result === 'OK'; // 'OK' = new key (not replay), null = key exists (replay)
    } catch (err) {
      logger.warn({ err, dedupeKey }, 'Redis replay check failed, falling back to in-memory');
      // Fall through to in-memory logic
    }
  }

  // In-memory fallback
  if (recentMessageIds.has(dedupeKey)) {
    return false; // replay
  }
  recentMessageIds.set(dedupeKey, Date.now());
  return true; // new message
}

async function handleMessage(ws: WebSocket, user: WsUser, msg: Record<string, unknown>): Promise<void> {
  switch (msg.type) {
    case WS_MSG_TYPE.MESSAGE:
      await handleChatMessage(ws, user, msg);
      return;
    case WS_MSG_TYPE.TYPING:
      handleTyping(user, msg);
      return;
    case WS_MSG_TYPE.READ_RECEIPT:
      handleReadReceipt(user, msg);
      return;
    case WS_MSG_TYPE.DISAPPEARING_TIMER:
      handleDisappearingTimer(user, msg);
      return;
    case WS_MSG_TYPE.ACK:
      handleAck(user, msg);
      return;
    default:
      sendError(ws, 'Unknown message type');
      return;
  }
}

async function handleChatMessage(ws: WebSocket, sender: WsUser, msg: Record<string, unknown>): Promise<void> {
  if (!msg.to || typeof msg.to !== 'string') {
    sendError(ws, 'Invalid recipient');
    return;
  }
  const message = msg.message as { body?: unknown; type?: unknown } | undefined;
  if (!message || !message.body || typeof message.body !== 'string') {
    sendError(ws, 'Invalid message format');
    return;
  }
  if (message.body.length > MAX_MESSAGE_BODY_SIZE) {
    sendError(ws, 'Message too large');
    return;
  }
  // Validate Signal message type (1 = Whisper, 3 = PreKey)
  if (message.type !== 1 && message.type !== 3) {
    sendError(ws, 'Invalid message type');
    return;
  }

  // C4: Validate msg.id and reject replays
  if (!msg.id || typeof msg.id !== 'string' || msg.id.length > 64) {
    sendError(ws, 'Invalid message ID');
    return;
  }
  const dedupeKey = `${sender.id}:${msg.id}`;
  const isNew = await checkReplay(dedupeKey);
  if (!isNew) {
    sendError(ws, 'Duplicate message ID');
    return;
  }

  const recipient = stmt.getUserByUsername.get(msg.to) as DbUser | undefined;
  if (!recipient) {
    sendError(ws, 'Recipient not found');
    return;
  }

  // Prevent self-messaging
  if (recipient.id === sender.id) {
    sendError(ws, 'Cannot send messages to yourself');
    return;
  }

  const timestamp = new Date().toISOString();

  // Check conversation disappearing timer
  const timerResult = stmt.getConversationTimer.get(sender.id, recipient.id, sender.id, recipient.id) as { disappearing_timer_ms: number } | undefined;
  const expiresAt = timerResult?.disappearing_timer_ms
    ? Math.floor(Date.now() / 1000) + Math.floor(timerResult.disappearing_timer_ms / 1000)
    : null;

  // M10: Wrap DB insert in try-catch (recipient could be deleted between lookup and insert)
  let storedMsgId: number | bigint;
  try {
    const result = stmt.storeMessageWithExpiry.run(sender.id, recipient.id, message.type, message.body, expiresAt);
    storedMsgId = result.lastInsertRowid;
  } catch (err) {
    logger.error({ err, senderId: sender.id, recipientId: recipient.id }, 'Failed to store message');
    sendError(ws, 'Failed to send message');
    return;
  }

  incr('messagesStored');

  if (isOnline(recipient.id)) {
    const recipientWs = getConnection(recipient.id);
    if (recipientWs) {
      send(recipientWs, {
        type: WS_MSG_TYPE.MESSAGE,
        from: sender.username,
        fromId: sender.id,
        message: message as { type: number; body: string },
        timestamp,
        id: msg.id,
        dbId: storedMsgId,
      });
    }
    send(ws, { type: WS_MSG_TYPE.STORED, id: msg.id, timestamp });
  } else {
    send(ws, { type: WS_MSG_TYPE.STORED, id: msg.id, timestamp });
  }
}

function handleAck(user: WsUser, msg: Record<string, unknown>): void {
  // Client acknowledges receipt of a message - now we can mark it delivered
  if (!msg.dbId || typeof msg.dbId !== 'number') return;
  // Atomically mark delivered and get actual sender_id from DB (prevents spoofing)
  const result = stmt.markDeliveredAndGetSender.get(msg.dbId, user.id) as DbMarkDeliveredResult | undefined;
  if (!result) return; // Not their message, already delivered, or not found
  incr('messagesDelivered');

  // Notify the actual sender (from DB, not client-supplied msg.from)
  if (isOnline(result.sender_id)) {
    const senderWs = getConnection(result.sender_id);
    if (senderWs) {
      send(senderWs, {
        type: WS_MSG_TYPE.DELIVERED,
        id: msg.originalId,
      });
    }
  }
}

function handleTyping(sender: WsUser, msg: Record<string, unknown>): void {
  if (!msg.to || typeof msg.to !== 'string') return;

  const recipient = stmt.getUserByUsername.get(msg.to) as DbUser | undefined;
  if (!recipient || !isOnline(recipient.id)) return;

  // Only relay typing to users with prior conversation (prevents presence leak to strangers)
  if (!stmt.hasConversation.get(sender.id, recipient.id, recipient.id, sender.id)) return;

  const recipientWs = getConnection(recipient.id);
  if (recipientWs) {
    send(recipientWs, {
      type: WS_MSG_TYPE.TYPING,
      from: sender.username,
      isTyping: !!msg.isTyping,
    });
  }
}

// C2: Read receipt now requires hasConversation check (was missing)
function handleReadReceipt(sender: WsUser, msg: Record<string, unknown>): void {
  if (!msg.to || typeof msg.to !== 'string') return;
  if (!Array.isArray(msg.messageIds) || msg.messageIds.length === 0 || msg.messageIds.length > 100) return;
  // Validate all messageIds are strings
  if (!msg.messageIds.every((id: unknown) => typeof id === 'string' && (id as string).length < 50)) return;

  const recipient = stmt.getUserByUsername.get(msg.to) as DbUser | undefined;
  if (!recipient || !isOnline(recipient.id)) return;

  // C2: Only relay read receipts to users with prior conversation
  if (!stmt.hasConversation.get(sender.id, recipient.id, recipient.id, sender.id)) return;

  const recipientWs = getConnection(recipient.id);
  if (recipientWs) {
    send(recipientWs, {
      type: WS_MSG_TYPE.READ_RECEIPT,
      from: sender.username,
      messageIds: msg.messageIds as string[],
    });
  }
}

// Valid disappearing timer values (seconds)
const VALID_TIMERS = new Set([0, 30, 300, 3600, 86400, 604800]);

function handleDisappearingTimer(sender: WsUser, msg: Record<string, unknown>): void {
  if (!msg.to || typeof msg.to !== 'string') return;
  if (typeof msg.timer !== 'number' || !VALID_TIMERS.has(msg.timer)) return;

  const recipient = stmt.getUserByUsername.get(msg.to) as DbUser | undefined;
  if (!recipient || !isOnline(recipient.id)) return;

  // Only relay timer changes to users with prior conversation
  if (!stmt.hasConversation.get(sender.id, recipient.id, recipient.id, sender.id)) return;

  const recipientWs = getConnection(recipient.id);
  if (recipientWs) {
    send(recipientWs, {
      type: WS_MSG_TYPE.DISAPPEARING_TIMER,
      from: sender.username,
      timer: msg.timer,
    });
  }

  // Persist timer server-side (msg.timer is in seconds, column is milliseconds)
  stmt.upsertConversationTimer.run(sender.id, recipient.id, sender.id, recipient.id, (msg.timer as number) * 1000);
}

function send(ws: WebSocket, data: unknown): void {
  if (ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify(data));
    incr('wsMessagesOut');
  }
}

function sendError(ws: WebSocket, message: string): void {
  send(ws, { type: WS_MSG_TYPE.ERROR, message });
}

export { handleMessage };
