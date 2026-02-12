const { getConnection, isOnline } = require('./connections');
const { stmt, audit } = require('../db');
const { WS_MSG_TYPE } = require('../../shared/constants');
const logger = require('../logger');
const { incr } = require('../metrics');

function handleMessage(ws, user, data) {
  let msg;
  try {
    msg = JSON.parse(data);
  } catch {
    return sendError(ws, 'Invalid JSON');
  }

  switch (msg.type) {
    case WS_MSG_TYPE.MESSAGE:
      return handleChatMessage(ws, user, msg);
    case WS_MSG_TYPE.TYPING:
      return handleTyping(user, msg);
    case WS_MSG_TYPE.READ_RECEIPT:
      return handleReadReceipt(user, msg);
    case WS_MSG_TYPE.DISAPPEARING_TIMER:
      return handleDisappearingTimer(user, msg);
    case WS_MSG_TYPE.ACK:
      return handleAck(user, msg);
    default:
      return sendError(ws, 'Unknown message type');
  }
}

function handleChatMessage(ws, sender, msg) {
  if (!msg.to || typeof msg.to !== 'string') {
    return sendError(ws, 'Invalid recipient');
  }
  if (!msg.message || !msg.message.body || typeof msg.message.body !== 'string') {
    return sendError(ws, 'Invalid message format');
  }
  // Validate Signal message type (1 = Whisper, 3 = PreKey)
  if (msg.message.type !== 1 && msg.message.type !== 3) {
    return sendError(ws, 'Invalid message type');
  }

  const recipient = stmt.getUserByUsername.get(msg.to);
  if (!recipient) {
    return sendError(ws, 'Recipient not found');
  }

  const timestamp = new Date().toISOString();

  // ALWAYS store the message first (store-then-send pattern)
  // This prevents message loss if the recipient's socket is stale
  const result = stmt.storeMessage.run(sender.id, recipient.id, msg.message.type, msg.message.body);
  const storedMsgId = result.lastInsertRowid;
  incr('messagesStored');

  if (isOnline(recipient.id)) {
    const recipientWs = getConnection(recipient.id);
    send(recipientWs, {
      type: WS_MSG_TYPE.MESSAGE,
      from: sender.username,
      fromId: sender.id,
      message: msg.message,
      timestamp,
      id: msg.id,
      dbId: storedMsgId, // for ACK-based delivery confirmation
    });
    // Don't mark as delivered yet - wait for client ACK
    send(ws, { type: WS_MSG_TYPE.STORED, id: msg.id, timestamp });
  } else {
    send(ws, { type: WS_MSG_TYPE.STORED, id: msg.id, timestamp });
  }
}

function handleAck(user, msg) {
  // Client acknowledges receipt of a message - now we can mark it delivered
  if (!msg.dbId || typeof msg.dbId !== 'number') return;
  // Ownership check: only the recipient can ACK their own messages
  const result = stmt.markDelivered.run(msg.dbId, user.id);
  if (result.changes === 0) return; // Not their message or already delivered
  incr('messagesDelivered');

  // Notify the sender that the message was delivered
  if (msg.from) {
    const sender = stmt.getUserByUsername.get(msg.from);
    if (sender && isOnline(sender.id)) {
      const senderWs = getConnection(sender.id);
      send(senderWs, {
        type: WS_MSG_TYPE.DELIVERED,
        id: msg.originalId, // the client-side message id
      });
    }
  }
}

function handleTyping(sender, msg) {
  if (!msg.to || typeof msg.to !== 'string') return;

  const recipient = stmt.getUserByUsername.get(msg.to);
  if (!recipient || !isOnline(recipient.id)) return;

  const recipientWs = getConnection(recipient.id);
  send(recipientWs, {
    type: WS_MSG_TYPE.TYPING,
    from: sender.username,
    isTyping: !!msg.isTyping,
  });
}

function handleReadReceipt(sender, msg) {
  if (!msg.to || typeof msg.to !== 'string') return;
  if (!Array.isArray(msg.messageIds) || msg.messageIds.length === 0 || msg.messageIds.length > 100) return;
  // Validate all messageIds are strings
  if (!msg.messageIds.every(id => typeof id === 'string' && id.length < 50)) return;

  const recipient = stmt.getUserByUsername.get(msg.to);
  if (!recipient || !isOnline(recipient.id)) return;

  const recipientWs = getConnection(recipient.id);
  send(recipientWs, {
    type: WS_MSG_TYPE.READ_RECEIPT,
    from: sender.username,
    messageIds: msg.messageIds,
  });
}

// Valid disappearing timer values (seconds)
const VALID_TIMERS = new Set([0, 30, 300, 3600, 86400, 604800]);

function handleDisappearingTimer(sender, msg) {
  if (!msg.to || typeof msg.to !== 'string') return;
  if (typeof msg.timer !== 'number' || !VALID_TIMERS.has(msg.timer)) return;

  const recipient = stmt.getUserByUsername.get(msg.to);
  if (!recipient || !isOnline(recipient.id)) return;

  const recipientWs = getConnection(recipient.id);
  send(recipientWs, {
    type: WS_MSG_TYPE.DISAPPEARING_TIMER,
    from: sender.username,
    timer: msg.timer,
  });
}

function send(ws, data) {
  if (ws.readyState === 1) {
    ws.send(JSON.stringify(data));
    incr('wsMessagesOut');
  }
}

function sendError(ws, message) {
  send(ws, { type: WS_MSG_TYPE.ERROR, message });
}

module.exports = { handleMessage };
