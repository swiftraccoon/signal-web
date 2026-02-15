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

module.exports = { addConnection, removeConnection, getConnection, isOnline };
