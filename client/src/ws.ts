import { getToken, api } from './api';
import { STORES, get, put, remove, getAll } from './storage/indexeddb';

let ws: WebSocket | null = null;
let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
let reconnectDelay = 1000;
let pingInterval: ReturnType<typeof setInterval> | null = null;
const MAX_RECONNECT_DELAY = 30000;
const PING_INTERVAL_MS = 25000;
const listeners = new Map<string, Set<(data?: unknown) => void>>();

// Offline message queue - messages sent while disconnected
interface QueuedMessage {
  type: string;
  [key: string]: unknown;
}

interface PersistedQueuedMessage {
  id: string;
  message: QueuedMessage;
  retries: number;
  queuedAt: number;
}

const MAX_QUEUE_SIZE = 100;
const MAX_RETRIES = 3;
const BASE_RETRY_DELAY = 1000; // 1 second
const JITTER_FACTOR = 0.3; // +/- 30%

// Retry timers keyed by queue entry ID
const retryTimers = new Map<string, ReturnType<typeof setTimeout>>();

function generateQueueId(): string {
  const rnd = crypto.getRandomValues(new Uint32Array(1))[0]!.toString(36);
  return Date.now().toString(36) + rnd;
}

function calculateRetryDelay(retryCount: number): number {
  // Exponential backoff: 1s, 2s, 4s
  const baseDelay = BASE_RETRY_DELAY * Math.pow(2, retryCount);
  // Add +/- 30% jitter
  const jitter = baseDelay * JITTER_FACTOR * (2 * Math.random() - 1);
  return Math.round(baseDelay + jitter);
}

async function queueMessage(msg: QueuedMessage): Promise<string> {
  // Check queue size first
  const { keys } = await getAll(STORES.MESSAGE_QUEUE);
  if (keys.length >= MAX_QUEUE_SIZE) {
    throw new Error('Message queue is full');
  }

  const id = generateQueueId();
  const entry: PersistedQueuedMessage = {
    id,
    message: msg,
    retries: 0,
    queuedAt: Date.now(),
  };
  await put(STORES.MESSAGE_QUEUE, id, entry);
  return id;
}

async function removeFromQueue(queueId: string): Promise<void> {
  await remove(STORES.MESSAGE_QUEUE, queueId);
  const timer = retryTimers.get(queueId);
  if (timer) {
    clearTimeout(timer);
    retryTimers.delete(queueId);
  }
}

async function flushQueue(): Promise<void> {
  const { values } = await getAll(STORES.MESSAGE_QUEUE);
  if (values.length === 0) return;

  // Sort by queuedAt to send in order
  const entries = (values as PersistedQueuedMessage[])
    .filter(Boolean)
    .sort((a, b) => a.queuedAt - b.queuedAt);

  for (const entry of entries) {
    if (ws && ws.readyState === WebSocket.OPEN) {
      try {
        ws.send(JSON.stringify(entry.message));
        await removeFromQueue(entry.id);
      } catch {
        // WS send failed, schedule retry
        scheduleRetry(entry);
      }
    } else {
      // WS not open, stop flushing
      break;
    }
  }
}

function scheduleRetry(entry: PersistedQueuedMessage): void {
  // Clear any existing timer for this entry
  const existing = retryTimers.get(entry.id);
  if (existing) {
    clearTimeout(existing);
    retryTimers.delete(entry.id);
  }

  if (entry.retries >= MAX_RETRIES) {
    // Max retries reached, emit send_failed
    emit('send_failed', { queueId: entry.id, message: entry.message });
    void removeFromQueue(entry.id);
    return;
  }

  const delay = calculateRetryDelay(entry.retries);
  const timer = setTimeout(async () => {
    retryTimers.delete(entry.id);
    await retrySend(entry.id);
  }, delay);
  retryTimers.set(entry.id, timer);
}

async function retrySend(queueId: string): Promise<void> {
  const stored = await get(STORES.MESSAGE_QUEUE, queueId) as PersistedQueuedMessage | undefined;
  if (!stored) return; // Already removed

  if (ws && ws.readyState === WebSocket.OPEN) {
    try {
      ws.send(JSON.stringify(stored.message));
      await removeFromQueue(queueId);
    } catch {
      // Increment retry count and persist
      stored.retries++;
      await put(STORES.MESSAGE_QUEUE, queueId, stored);
      scheduleRetry(stored);
    }
  } else {
    // WS not open, increment retries and schedule again
    stored.retries++;
    await put(STORES.MESSAGE_QUEUE, queueId, stored);
    scheduleRetry(stored);
  }
}

// Re-queue a message that previously failed (called from retry UI)
async function requeueMessage(msg: QueuedMessage): Promise<void> {
  await queueMessage(msg);
  // If connected, try to flush immediately
  if (ws && ws.readyState === WebSocket.OPEN) {
    await flushQueue();
  }
}

async function connect(): Promise<void> {
  const token = getToken();
  if (!token) return;

  // Get a short-lived one-time ticket for WS auth (never send JWT in URL)
  let ticket: string;
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
    if (reconnectTimer) clearTimeout(reconnectTimer);
    reconnectDelay = 1000;
    emit('open');
    showConnectionStatus(true);

    // Start client-side keepalive pings (server pings every 30s, we ping every 25s)
    if (pingInterval) clearInterval(pingInterval);
    pingInterval = setInterval(() => {
      if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: 'ping' }));
      }
    }, PING_INTERVAL_MS);

    // Flush queued messages from IndexedDB
    void flushQueue();
  };

  ws.onmessage = (e: MessageEvent) => {
    try {
      const data = JSON.parse(e.data as string) as Record<string, unknown>;
      // Validate that the message has a known type
      if (!data || typeof data.type !== 'string') return;
      emit(data.type, data);
    } catch {
      // ignore malformed messages
    }
  };

  ws.onclose = (e: CloseEvent) => {
    ws = null;
    if (pingInterval) {
      clearInterval(pingInterval);
      pingInterval = null;
    }
    emit('close');
    showConnectionStatus(false);
    // Don't reconnect on auth failure
    if (e.code === 4001 || e.code === 4003) return;
    if (getToken()) {
      reconnectTimer = setTimeout(connect, reconnectDelay);
      const jitter = 0.7 + Math.random() * 0.6; // +/-30%
      reconnectDelay = Math.min(reconnectDelay * 2 * jitter, MAX_RECONNECT_DELAY);
    }
  };

  ws.onerror = () => {
    // onclose will fire after this
  };
}

function disconnect(): void {
  if (reconnectTimer) clearTimeout(reconnectTimer);
  if (pingInterval) {
    clearInterval(pingInterval);
    pingInterval = null;
  }
  reconnectDelay = 1000;
  // Clear all retry timers
  for (const [, timer] of retryTimers) {
    // eslint-disable-next-line @typescript-eslint/no-unsafe-argument -- Map<string, ReturnType<typeof setTimeout>> iteration; type not resolved by project service
    clearTimeout(timer);
  }
  retryTimers.clear();
  if (ws) {
    ws.close();
    ws = null;
  }
  showConnectionStatus(null); // hide
}

function send(data: QueuedMessage): void {
  if (ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify(data));
  } else {
    queueMessage(data).catch((err) => {
      console.error('Failed to queue message:', err);
    });
  }
}

function isConnected(): boolean {
  return ws !== null && ws.readyState === WebSocket.OPEN;
}

function on(type: string, fn: (data?: unknown) => void): void {
  if (!listeners.has(type)) listeners.set(type, new Set());
  listeners.get(type)!.add(fn);
}

function off(type: string, fn: (data?: unknown) => void): void {
  const set = listeners.get(type);
  if (set) set.delete(fn);
}

function emit(type: string, data?: unknown): void {
  const set = listeners.get(type);
  if (set) {
    // eslint-disable-next-line @typescript-eslint/no-unsafe-call -- Set<(data?: unknown) => void> iteration; type not resolved by project service
    for (const fn of set) fn(data);
  }
}

function showConnectionStatus(connected: boolean | null): void {
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

export { connect, disconnect, send, on, off, isConnected, requeueMessage };
