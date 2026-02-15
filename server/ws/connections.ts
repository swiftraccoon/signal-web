import WebSocket from 'ws';

// userId -> WebSocket map
const connections = new Map<number, WebSocket>();

function addConnection(userId: number, ws: WebSocket): void {
  const existing = connections.get(userId);
  if (existing && existing.readyState <= WebSocket.OPEN) {
    existing.close(4000, 'Replaced by new connection');
  }
  connections.set(userId, ws);
}

function removeConnection(userId: number, ws: WebSocket): void {
  // Only remove if the current connection matches (avoids race with replacement)
  const current = connections.get(userId);
  if (current === ws) {
    connections.delete(userId);
  }
}

function getConnection(userId: number): WebSocket | undefined {
  return connections.get(userId);
}

function isOnline(userId: number): boolean {
  const ws = connections.get(userId);
  return ws !== undefined && ws.readyState === WebSocket.OPEN;
}

export { addConnection, removeConnection, getConnection, isOnline };
