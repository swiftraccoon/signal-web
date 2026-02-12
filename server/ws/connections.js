// userId -> WebSocket map
const connections = new Map();
// Track which userIds each user has interest in (for presence)
// Not needed — we broadcast presence to all contacts via handler

function addConnection(userId, ws) {
  const existing = connections.get(userId);
  if (existing && existing.readyState <= 1) {
    existing.close(4000, 'Replaced by new connection');
  }
  connections.set(userId, ws);
}

function removeConnection(userId, ws) {
  // Only remove if the current connection matches (avoids race with replacement)
  const current = connections.get(userId);
  if (current === ws) {
    connections.delete(userId);
  }
}

function getConnection(userId) {
  return connections.get(userId);
}

function isOnline(userId) {
  const ws = connections.get(userId);
  return ws && ws.readyState === 1; // WebSocket.OPEN
}

function getAllOnlineUserIds() {
  const ids = [];
  for (const [userId, ws] of connections.entries()) {
    if (ws.readyState === 1) ids.push(userId);
  }
  return ids;
}

function broadcastToAll(data, excludeUserId) {
  const json = JSON.stringify(data);
  for (const [userId, ws] of connections.entries()) {
    if (userId !== excludeUserId && ws.readyState === 1) {
      ws.send(json);
    }
  }
}

module.exports = { addConnection, removeConnection, getConnection, isOnline, getAllOnlineUserIds, broadcastToAll };
