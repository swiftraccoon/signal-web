import { getToken, api } from './api.js';

let ws = null;
let reconnectTimer = null;
let reconnectDelay = 1000;
const MAX_RECONNECT_DELAY = 30000;
const listeners = new Map();

// Offline message queue - messages sent while disconnected
const messageQueue = [];
const MAX_QUEUE_SIZE = 100;

async function connect() {
  const token = getToken();
  if (!token) return;

  // Get a short-lived one-time ticket for WS auth (never send JWT in URL)
  let ticket;
  try {
    const resp = await api.getWsTicket();
    ticket = resp.ticket;
  } catch {
    console.error('Failed to obtain WS ticket');
    return; // Do NOT fall back to sending JWT in URL (leaks to proxy logs, history)
  }

  const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
  ws = new WebSocket(`${protocol}//${location.host}?ticket=${ticket}`);

  ws.onopen = () => {
    clearTimeout(reconnectTimer);
    reconnectDelay = 1000;
    emit('open');
    showConnectionStatus(true);

    // Flush queued messages
    while (messageQueue.length > 0) {
      const msg = messageQueue.shift();
      ws.send(JSON.stringify(msg));
    }
  };

  ws.onmessage = (e) => {
    try {
      const data = JSON.parse(e.data);
      // Validate that the message has a known type
      if (!data || typeof data.type !== 'string') return;
      emit(data.type, data);
    } catch {
      // ignore malformed messages
    }
  };

  ws.onclose = (e) => {
    ws = null;
    emit('close');
    showConnectionStatus(false);
    // Don't reconnect on auth failure
    if (e.code === 4001 || e.code === 4003) return;
    if (getToken()) {
      reconnectTimer = setTimeout(connect, reconnectDelay);
      reconnectDelay = Math.min(reconnectDelay * 2, MAX_RECONNECT_DELAY);
    }
  };

  ws.onerror = () => {
    // onclose will fire after this
  };
}

function disconnect() {
  clearTimeout(reconnectTimer);
  reconnectDelay = 1000;
  messageQueue.length = 0;
  if (ws) {
    ws.close();
    ws = null;
  }
  showConnectionStatus(null); // hide
}

function send(data) {
  if (ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify(data));
  } else {
    // Queue for sending when reconnected (except typing indicators)
    if (data.type !== 'typing' && messageQueue.length < MAX_QUEUE_SIZE) {
      messageQueue.push(data);
    }
  }
}

function isConnected() {
  return ws && ws.readyState === WebSocket.OPEN;
}

function on(type, fn) {
  if (!listeners.has(type)) listeners.set(type, new Set());
  listeners.get(type).add(fn);
}

function off(type, fn) {
  const set = listeners.get(type);
  if (set) set.delete(fn);
}

function emit(type, data) {
  const set = listeners.get(type);
  if (set) {
    for (const fn of set) fn(data);
  }
}

function showConnectionStatus(connected) {
  let banner = document.getElementById('connection-banner');
  if (connected === null) {
    // Hide
    if (banner) banner.classList.add('hidden');
    return;
  }
  if (!banner) {
    // Create banner if it doesn't exist
    banner = document.createElement('div');
    banner.id = 'connection-banner';
    const chatView = document.getElementById('chat-view');
    if (chatView) chatView.prepend(banner);
  }
  if (connected) {
    banner.classList.add('hidden');
  } else {
    banner.textContent = 'Reconnecting...';
    banner.className = 'connection-banner';
  }
}

export { connect, disconnect, send, on, off, isConnected };
