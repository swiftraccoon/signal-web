import { STORES, get, put, putDebounced } from '../storage/indexeddb';
import QRCode from 'qrcode';
import { encryptMessage, decryptMessage } from '../signal/client';
import { send as wsSend, on as wsOn, requeueMessage } from '../ws';
import { getContactInfo, updateLastMessage } from './contacts';
import { showToast } from './notifications';
import { WS_MSG_TYPE } from '../../../shared/constants';
import type { ChatMessage, WsServerDeliveredMessage, WsServerReadReceiptMessage, WsServerDisappearingTimerMessage } from '../../../shared/types';

let currentChat: string | null = null; // username
let messageHistory: Record<string, ChatMessage[]> = {};
let disappearingTimers: Record<string, number> = {};
let disappearIntervals: Record<string, ReturnType<typeof setInterval>> = {};
let renderScheduled = false; // rAF debounce flag

function setLoading(btn: HTMLButtonElement, loading: boolean, originalText: string): void {
  if (loading) {
    btn.classList.add('btn-loading');
    btn.textContent = '';
    const spinner = document.createElement('span');
    spinner.className = 'spinner';
    btn.appendChild(spinner);
  } else {
    btn.classList.remove('btn-loading');
    btn.textContent = originalText;
  }
}
// Persistent msgId -> username mapping backed by IndexedDB (MESSAGE_STATUS store)
async function trackMessageId(msgId: string, username: string): Promise<void> {
  await put(STORES.MESSAGE_STATUS, msgId, username);
}
async function getMessageUsername(msgId: string): Promise<string | undefined> {
  return (await get(STORES.MESSAGE_STATUS, msgId)) as string | undefined;
}

// Track failed messages for retry UI
interface FailedMessageInfo {
  queueId: string;
  message: { type: string; [key: string]: unknown };
}
const failedMessages = new Map<string, FailedMessageInfo>(); // msgId -> failed info

// URL regex - matches http/https URLs
const URL_REGEX = /https?:\/\/[^\s<>"')\]]+/g;

export function initChat(): void {
  const form = document.getElementById('message-form') as HTMLFormElement;
  const input = document.getElementById('message-input') as HTMLInputElement;
  const sendBtn = form.querySelector('button[type="submit"]') as HTMLButtonElement;

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const text = input.value.trim();
    if (!text || !currentChat) return;

    const contact = getContactInfo(currentChat);
    if (!contact) return;

    input.value = '';
    input.disabled = true;
    setLoading(sendBtn, true, 'Send');

    try {
      const encrypted = await encryptMessage(currentChat, contact.id, text);

      const rnd = crypto.getRandomValues(new Uint32Array(1))[0]!.toString(36);
      const msgId = Date.now().toString(36) + rnd;

      wsSend({
        type: WS_MSG_TYPE.MESSAGE,
        to: currentChat,
        message: encrypted,
        id: msgId,
      });

      const msg: ChatMessage = {
        text,
        sent: true,
        time: new Date().toISOString(),
        id: msgId,
        status: 'sent', // sent -> delivered -> read
      };

      // If disappearing messages are on, set expiry
      const timer = disappearingTimers[currentChat];
      if (timer && timer > 0) {
        msg.disappearAt = Date.now() + timer * 1000;
      }

      addMessage(currentChat, msg);
      // Don't persist plaintext preview when disappearing messages are enabled
      const preview = (disappearingTimers[currentChat]! > 0) ? '' : text;
      updateLastMessage(currentChat, preview, msg.time);
    } catch (err) {
      console.error('Encrypt/send error:', err);
      const errorMsg = (err as Error).message || '';
      let friendlyMsg = "Couldn't send your message. Please try again.";
      if (errorMsg.includes('network') || errorMsg.includes('fetch')) {
        friendlyMsg = "Can't reach the server — retrying...";
      } else if (errorMsg.includes('encrypt') || errorMsg.includes('key') || errorMsg.includes('session')) {
        friendlyMsg = "Encryption error — try re-opening the chat.";
      } else if (errorMsg.includes('not found') || errorMsg.includes('recipient')) {
        friendlyMsg = "That user could not be found.";
      }
      showToast(friendlyMsg, 'error');
    } finally {
      setLoading(sendBtn, false, 'Send');
      input.disabled = false;
      input.focus();
    }
  });

  // Typing indicator (throttled to avoid hitting server rate limits)
  let typingTimeout: ReturnType<typeof setTimeout> | null = null;
  let lastTypingSent = 0;
  const TYPING_THROTTLE_MS = 500;
  input.addEventListener('input', () => {
    if (!currentChat) return;
    const now = Date.now();
    if (now - lastTypingSent >= TYPING_THROTTLE_MS) {
      wsSend({ type: WS_MSG_TYPE.TYPING, to: currentChat, isTyping: true });
      lastTypingSent = now;
    }
    if (typingTimeout) clearTimeout(typingTimeout);
    typingTimeout = setTimeout(() => {
      wsSend({ type: WS_MSG_TYPE.TYPING, to: currentChat!, isTyping: false });
    }, 5000);
  });

  // Disappearing messages menu
  const disappearingBtn = document.getElementById('disappearing-btn')!;
  const disappearingMenu = document.getElementById('disappearing-menu')!;

  disappearingBtn.addEventListener('click', () => {
    disappearingMenu.classList.toggle('hidden');
    updateDisappearingMenuActive();
  });

  disappearingMenu.addEventListener('click', (e) => {
    const option = (e.target as HTMLElement).closest('.disappearing-option') as HTMLElement | null;
    if (!option) return;
    const timer = parseInt(option.dataset.timer!, 10);
    setDisappearingTimer(currentChat!, timer);
    disappearingMenu.classList.add('hidden');
  });

  // Close menu on outside click
  document.addEventListener('click', (e) => {
    if (!disappearingBtn.contains(e.target as Node) && !disappearingMenu.contains(e.target as Node)) {
      disappearingMenu.classList.add('hidden');
    }
  });

  // Safety number button
  document.getElementById('safety-number-btn')!.addEventListener('click', () => {
    if (currentChat) showSafetyNumber(currentChat);
  });

  // Mobile back button
  document.getElementById('chat-back-btn')!.addEventListener('click', () => {
    document.getElementById('sidebar')!.classList.remove('sidebar-hidden');
    document.getElementById('chat-active')!.classList.add('hidden');
    document.getElementById('chat-placeholder')!.classList.remove('hidden');
    currentChat = null;
  });

  // Listen for send_failed events to show retry buttons
  wsOn('send_failed', (data?: unknown) => {
    const failedData = data as { queueId: string; message: { type: string; id?: string; to?: string; [key: string]: unknown } } | undefined;
    if (!failedData || !failedData.message) return;

    const msgId = failedData.message.id as string | undefined;
    if (!msgId) return;

    failedMessages.set(msgId, {
      queueId: failedData.queueId,
      message: failedData.message,
    });

    // Update the message status in history
    const username = failedData.message.to as string | undefined;
    if (username && messageHistory[username]) {
      for (const msg of messageHistory[username]!) {
        if (msg.id === msgId && msg.sent) {
          msg.status = 'sent'; // Keep as sent but UI will show retry based on failedMessages map
          break;
        }
      }
    }

    // Re-render if we're viewing this chat
    if (username && currentChat === username) {
      scheduleRender(username);
    }
  });
}

export async function openChat(username: string): Promise<void> {
  currentChat = username;

  document.getElementById('chat-placeholder')!.classList.add('hidden');
  document.getElementById('chat-active')!.classList.remove('hidden');
  document.getElementById('chat-recipient')!.textContent = username;
  document.getElementById('disappearing-menu')!.classList.add('hidden');

  // Hide sidebar on mobile
  if (window.innerWidth <= 768) {
    document.getElementById('sidebar')!.classList.add('sidebar-hidden');
  }

  // Load disappearing timer setting
  const storedTimer = await get(STORES.META, `disappear:${username}`) as number | undefined;
  disappearingTimers[username] = storedTimer || 0;
  updateDisappearingBanner(username);

  // Load message history from IndexedDB
  if (!messageHistory[username]) {
    const stored = await get(STORES.MESSAGES, username) as ChatMessage[] | undefined;
    messageHistory[username] = stored || [];
  }

  // Purge expired disappearing messages
  purgeExpiredMessages(username);

  renderMessages(username);
  (document.getElementById('message-input') as HTMLInputElement).focus();

  // Send read receipts for unread messages
  sendReadReceipts(username);

  // Start disappearing message checker
  startDisappearChecker(username);
}

interface IncomingMessageData {
  from: string;
  fromId?: number;
  message: { type: number; body: string };
  timestamp?: string;
  id?: string;
  dbId?: number;
}

export async function handleIncomingMessage(data: IncomingMessageData): Promise<{ from: string; text: string | null }> {
  try {
    const plaintext = await decryptMessage(data.from, data.message);

    const msg: ChatMessage = {
      text: plaintext,
      sent: false,
      time: data.timestamp || new Date().toISOString(),
      id: data.id,
    };

    // If disappearing messages are on for this contact, set expiry
    const timer = disappearingTimers[data.from];
    if (timer && timer > 0) {
      msg.disappearAt = Date.now() + timer * 1000;
    }

    addMessage(data.from, msg);
    // Don't persist plaintext preview when disappearing messages are enabled
    const preview = (disappearingTimers[data.from]! > 0) ? '' : plaintext;
    updateLastMessage(data.from, preview, msg.time);

    // ACK receipt to server so it marks the message as delivered
    if (data.dbId) {
      wsSend({
        type: WS_MSG_TYPE.ACK,
        dbId: data.dbId,
        from: data.from,
        originalId: data.id!,
      });
    }

    // If this chat is currently open, send read receipt immediately
    if (currentChat === data.from && document.visibilityState === 'visible') {
      wsSend({
        type: WS_MSG_TYPE.READ_RECEIPT,
        to: data.from,
        messageIds: [data.id!],
      });
    }

    return { from: data.from, text: plaintext };
  } catch (err) {
    console.error('Decrypt error:', err);
    // Don't ACK — leave the message pending on the server so it can be retried on next login
    addMessage(data.from, {
      text: '[Decryption failed \u2014 will retry on next login]',
      sent: false,
      time: data.timestamp || new Date().toISOString(),
      error: true,
    });
    return { from: data.from, text: null };
  }
}

// Handle delivery confirmation from server
export async function handleDelivered(data: WsServerDeliveredMessage): Promise<void> {
  await updateMessageStatus(data.id, 'delivered');
}

// Handle read receipts from contact
export async function handleReadReceipt(data: WsServerReadReceiptMessage): Promise<void> {
  if (!data.messageIds || !data.from) return;
  for (const msgId of data.messageIds) {
    await updateMessageStatus(msgId, 'read');
  }
}

// Handle disappearing timer change from contact
export function handleDisappearingTimerChange(data: WsServerDisappearingTimerMessage): void {
  if (!data.from || data.timer === undefined) return;
  disappearingTimers[data.from] = data.timer;
  put(STORES.META, `disappear:${data.from}`, data.timer);

  if (currentChat === data.from) {
    updateDisappearingBanner(data.from);
  }

  // Add system message
  const timerText = formatTimerLabel(data.timer);
  addSystemMessage(data.from, `${data.from} set disappearing messages to ${timerText}`);
}

function setDisappearingTimer(username: string, timer: number): void {
  disappearingTimers[username] = timer;
  put(STORES.META, `disappear:${username}`, timer);
  updateDisappearingBanner(username);

  // Notify the other user
  wsSend({
    type: WS_MSG_TYPE.DISAPPEARING_TIMER,
    to: username,
    timer,
  });

  // Add system message
  const timerText = formatTimerLabel(timer);
  addSystemMessage(username, `You set disappearing messages to ${timerText}`);
}

function formatTimerLabel(seconds: number): string {
  if (seconds === 0) return 'off';
  if (seconds < 60) return `${seconds} seconds`;
  if (seconds < 3600) return `${seconds / 60} minutes`;
  if (seconds < 86400) return `${seconds / 3600} hour${seconds >= 7200 ? 's' : ''}`;
  return `${seconds / 86400} day${seconds >= 172800 ? 's' : ''}`;
}

function formatTimer(seconds: number): string {
  if (seconds < 60) return `${seconds} seconds`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)} minutes`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)} hour${Math.floor(seconds / 3600) > 1 ? 's' : ''}`;
  return `${Math.floor(seconds / 86400)} day${Math.floor(seconds / 86400) > 1 ? 's' : ''}`;
}

function updateDisappearingBanner(username: string): void {
  const banner = document.getElementById('disappearing-banner')!;
  const timer = disappearingTimers[username];
  if (timer && timer > 0) {
    banner.textContent = `Messages disappear after ${formatTimer(timer)}`;
    banner.classList.remove('hidden');
  } else {
    banner.classList.add('hidden');
  }
}

function updateDisappearingMenuActive(): void {
  const timer = disappearingTimers[currentChat!] || 0;
  const options = document.querySelectorAll('.disappearing-option');
  for (const opt of options) {
    if (parseInt((opt as HTMLElement).dataset.timer!, 10) === timer) {
      opt.classList.add('active');
    } else {
      opt.classList.remove('active');
    }
  }
}

async function updateMessageStatus(msgId: string, status: 'delivered' | 'read'): Promise<void> {
  // O(1) lookup using IndexedDB-backed message status store
  const username = await getMessageUsername(msgId);
  if (username) {
    const msgs = messageHistory[username];
    if (msgs) {
      for (const msg of msgs) {
        if (msg.id === msgId && msg.sent) {
          const order: Record<string, number> = { sent: 0, delivered: 1, read: 2 };
          if ((order[status] || 0) > (order[msg.status || 'sent'] || 0)) {
            msg.status = status;
            putDebounced(STORES.MESSAGES, username, messageHistory[username]!);
            if (currentChat === username) scheduleRender(username);
          }
          return;
        }
      }
    }
  }
  // Fallback: linear scan if not in IndexedDB (e.g. loaded from storage)
  for (const uname in messageHistory) {
    const msgs = messageHistory[uname]!;
    for (const msg of msgs) {
      if (msg.id === msgId && msg.sent) {
        const order: Record<string, number> = { sent: 0, delivered: 1, read: 2 };
        if ((order[status] || 0) > (order[msg.status || 'sent'] || 0)) {
          msg.status = status;
          await trackMessageId(msgId, uname);
          putDebounced(STORES.MESSAGES, uname, messageHistory[uname]!);
          if (currentChat === uname) scheduleRender(uname);
        }
        return;
      }
    }
  }
}

function sendReadReceipts(username: string): void {
  const msgs = messageHistory[username] || [];
  const unreadIds = msgs
    .filter(m => !m.sent && m.id && !m.readReceiptSent)
    .map(m => m.id!);

  if (unreadIds.length > 0) {
    wsSend({
      type: WS_MSG_TYPE.READ_RECEIPT,
      to: username,
      messageIds: unreadIds,
    });
    for (const msg of msgs) {
      if (msg.id && unreadIds.includes(msg.id)) {
        msg.readReceiptSent = true;
      }
    }
    putDebounced(STORES.MESSAGES, username, msgs);
  }
}

export function addSystemMessage(username: string, text: string): void {
  if (!messageHistory[username]) messageHistory[username] = [];
  messageHistory[username]!.push({ system: true, text, sent: false, time: new Date().toISOString() });

  const history = messageHistory[username]!.slice(-500);
  messageHistory[username] = history;
  putDebounced(STORES.MESSAGES, username, history);

  if (currentChat === username) scheduleRender(username);
}

function addMessage(username: string, msg: ChatMessage): void {
  if (!messageHistory[username]) messageHistory[username] = [];
  messageHistory[username]!.push(msg);

  // Track in IndexedDB for persistent O(1) status updates
  if (msg.id) {
    trackMessageId(msg.id, username);
  }

  // Persist to IndexedDB (keep last 500 messages per contact)
  const history = messageHistory[username]!.slice(-500);
  messageHistory[username] = history;
  putDebounced(STORES.MESSAGES, username, history);

  if (currentChat === username) {
    scheduleRender(username);
  }
}

function purgeExpiredMessages(username: string): void {
  const msgs = messageHistory[username];
  if (!msgs) return;
  const now = Date.now();
  let changed = false;
  const filtered: ChatMessage[] = [];
  for (const m of msgs) {
    if (m.disappearAt && m.disappearAt <= now) {
      // M3: Scrub plaintext from memory before discarding
      m.text = '';
      changed = true;
    } else {
      filtered.push(m);
    }
  }
  if (changed) {
    messageHistory[username] = filtered;
    putDebounced(STORES.MESSAGES, username, filtered);
  }
}

// rAF-debounced render to avoid redundant DOM thrashing
function scheduleRender(username: string): void {
  if (renderScheduled) return;
  renderScheduled = true;
  requestAnimationFrame(() => {
    renderScheduled = false;
    if (currentChat === username) renderMessages(username);
  });
}

function startDisappearChecker(username: string): void {
  // Clear any existing interval for previous chat
  for (const key in disappearIntervals) {
    clearInterval(disappearIntervals[key]);
    delete disappearIntervals[key];
  }

  if (disappearingTimers[username] && disappearingTimers[username]! > 0) {
    disappearIntervals[username] = setInterval(() => {
      const before = (messageHistory[username] || []).length;
      purgeExpiredMessages(username);
      if ((messageHistory[username] || []).length !== before && currentChat === username) {
        renderMessages(username);
      }
    }, 1000);
  }
}

function renderMessages(username: string): void {
  const container = document.getElementById('messages-container')!;
  while (container.firstChild) container.removeChild(container.firstChild);

  const messages = messageHistory[username] || [];
  let lastDateStr: string | null = null;

  for (const msg of messages) {
    // Date separator
    const dateStr = formatDateHeader(msg.time);
    if (dateStr !== lastDateStr) {
      lastDateStr = dateStr;
      const sep = document.createElement('div');
      sep.className = 'date-separator';
      const sepText = document.createElement('span');
      sepText.textContent = dateStr;
      sep.appendChild(sepText);
      container.appendChild(sep);
    }

    // System message
    if (msg.system) {
      const sysDiv = document.createElement('div');
      sysDiv.className = 'system-message';
      const sysSpan = document.createElement('span');
      sysSpan.textContent = msg.text;
      sysDiv.appendChild(sysSpan);
      container.appendChild(sysDiv);
      continue;
    }

    const div = document.createElement('div');
    div.className = `message ${msg.sent ? 'sent' : 'received'}`;
    if (msg.disappearAt) div.classList.add('disappearing');

    const textEl = document.createElement('div');
    textEl.className = 'message-text';
    if (msg.error) {
      textEl.className = 'message-error';
      textEl.textContent = msg.text;
    } else {
      renderTextWithLinks(textEl, msg.text);
    }

    const footer = document.createElement('div');
    footer.className = 'message-footer';

    const timeEl = document.createElement('span');
    timeEl.className = 'message-time';
    timeEl.textContent = formatTime(msg.time);
    footer.appendChild(timeEl);

    // Status indicators for sent messages
    if (msg.sent && !msg.error) {
      const statusEl = document.createElement('span');
      // L2: Validate status before using as CSS class
      const VALID_STATUSES = new Set(['sent', 'delivered', 'read']);
      const safeStatus = VALID_STATUSES.has(msg.status || 'sent') ? (msg.status || 'sent') : 'sent';
      statusEl.className = `message-status ${safeStatus}`;
      if (msg.status === 'read') {
        statusEl.textContent = '\u2713\u2713'; // double check
      } else if (msg.status === 'delivered') {
        statusEl.textContent = '\u2713\u2713'; // double check
      } else {
        statusEl.textContent = '\u2713'; // single check
      }
      footer.appendChild(statusEl);
    }

    div.appendChild(textEl);
    div.appendChild(footer);

    // Show retry button for failed messages
    if (msg.sent && msg.id && failedMessages.has(msg.id)) {
      div.classList.add('send-failed');
      const retryBtn = document.createElement('button');
      retryBtn.className = 'retry-btn';
      retryBtn.textContent = 'Retry';
      retryBtn.type = 'button';
      const failedMsgId = msg.id;
      retryBtn.addEventListener('click', () => {
        const failedInfo = failedMessages.get(failedMsgId);
        if (failedInfo) {
          failedMessages.delete(failedMsgId);
          requeueMessage(failedInfo.message);
          // Re-render to remove the retry button
          if (currentChat) scheduleRender(currentChat);
        }
      });
      div.appendChild(retryBtn);
    }

    container.appendChild(div);
  }

  container.scrollTop = container.scrollHeight;
}

// M4: Strip RTL/LTR override characters that can spoof message display
const BIDI_OVERRIDE_REGEX = /[\u202A-\u202E\u2066-\u2069\u200F\u200E]/g;

function sanitizeText(text: string): string {
  // M4: Remove bidirectional override characters
  return text.replace(BIDI_OVERRIDE_REGEX, '');
}

// L1: Validate URLs with URL constructor to prevent malformed/dangerous hrefs
function isValidHttpUrl(str: string): boolean {
  try {
    const url = new URL(str);
    return url.protocol === 'http:' || url.protocol === 'https:';
  } catch {
    return false;
  }
}

function renderTextWithLinks(element: HTMLElement, text: string): void {
  if (!text) return;
  const safeText = sanitizeText(text);
  const matches = [...safeText.matchAll(URL_REGEX)];
  if (matches.length === 0) {
    element.textContent = safeText;
    return;
  }

  let lastIndex = 0;
  for (const match of matches) {
    // Text before the URL
    if (match.index! > lastIndex) {
      element.appendChild(document.createTextNode(safeText.slice(lastIndex, match.index)));
    }
    // L1: Only create anchor if URL is valid http/https
    if (isValidHttpUrl(match[0])) {
      const a = document.createElement('a');
      a.href = match[0];
      a.textContent = match[0];
      a.target = '_blank';
      a.rel = 'noopener noreferrer';
      element.appendChild(a);
    } else {
      element.appendChild(document.createTextNode(match[0]));
    }
    lastIndex = match.index! + match[0].length;
  }
  // Remaining text after last URL
  if (lastIndex < safeText.length) {
    element.appendChild(document.createTextNode(safeText.slice(lastIndex)));
  }
}

export function showTypingIndicator(from: string, isTyping: boolean): void {
  if (from === currentChat) {
    const indicator = document.getElementById('typing-indicator')!;
    if (isTyping) {
      indicator.classList.remove('hidden');
    } else {
      indicator.classList.add('hidden');
    }
  }
}


function formatTime(isoString: string): string {
  try {
    const d = new Date(isoString);
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  } catch {
    return '';
  }
}

function formatDateHeader(isoString: string): string {
  try {
    const d = new Date(isoString);
    const now = new Date();
    const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
    const msgDate = new Date(d.getFullYear(), d.getMonth(), d.getDate());
    const diff = (today.getTime() - msgDate.getTime()) / (1000 * 60 * 60 * 24);

    if (diff === 0) return 'Today';
    if (diff === 1) return 'Yesterday';
    if (diff < 7) return d.toLocaleDateString([], { weekday: 'long' });
    return d.toLocaleDateString([], { year: 'numeric', month: 'long', day: 'numeric' });
  } catch {
    return '';
  }
}

async function showSafetyNumber(username: string): Promise<void> {
  const { getStore } = await import('../signal/client');
  const { getCurrentUser } = await import('../api');

  const user = getCurrentUser();
  if (!user) {
    showToast('Not logged in', 'error');
    return;
  }

  const store = getStore();
  const myIdentity = await store.getIdentityKeyPair();
  const theirIdentity = await store.loadIdentityKey(username);

  if (!myIdentity || !theirIdentity) {
    showToast('No identity keys available yet. Send a message first.', 'info');
    return;
  }

  // Generate fingerprint using iterative hashing (like Signal's NumericFingerprint)
  const myPub = new Uint8Array(myIdentity.pubKey);
  const theirPub = new Uint8Array(theirIdentity);

  // Hash each key iteratively 5200 times (per Signal spec)
  async function iterativeHash(publicKey: Uint8Array, stableIdentifier: string): Promise<Uint8Array> {
    const enc = new TextEncoder();
    const idBytes = enc.encode(stableIdentifier);
    let data = publicKey;
    for (let i = 0; i < 5200; i++) {
      // Hash(version || publicKey || stableIdentifier)
      const input = new Uint8Array(2 + data.length + idBytes.length);
      input[0] = 0; input[1] = 0; // version 0
      input.set(data, 2);
      input.set(idBytes, 2 + data.length);
      const hash = await crypto.subtle.digest('SHA-512', input);
      data = new Uint8Array(hash);
    }
    return data;
  }

  const myFingerprint = await iterativeHash(myPub, user.username);
  const theirFingerprint = await iterativeHash(theirPub, username);

  // Sort and concatenate for consistent ordering
  let combinedFingerprint: Uint8Array;
  if (compareBytes(myFingerprint, theirFingerprint) < 0) {
    combinedFingerprint = new Uint8Array([...myFingerprint, ...theirFingerprint]);
  } else {
    combinedFingerprint = new Uint8Array([...theirFingerprint, ...myFingerprint]);
  }

  // Format as 12 groups of 5 digits (like Signal)
  const hashArray = combinedFingerprint;
  let fingerprint = '';
  for (let i = 0; i < 30; i++) {
    const val = ((hashArray[i * 2 % hashArray.length]! << 8) | hashArray[(i * 2 + 1) % hashArray.length]!) % 100000;
    fingerprint += val.toString().padStart(5, '0');
    if ((i + 1) % 5 === 0) fingerprint += '\n';
    else fingerprint += ' ';
  }

  document.getElementById('safety-fingerprint')!.textContent = fingerprint.trim();
  document.getElementById('safety-you')!.textContent = user.username;
  document.getElementById('safety-them')!.textContent = username;

  // Render QR code from the fingerprint
  const qrContainer = document.getElementById('safety-qr')!;
  while (qrContainer.firstChild) qrContainer.removeChild(qrContainer.firstChild);
  const canvas = document.createElement('canvas');
  await QRCode.toCanvas(canvas, fingerprint.replace(/\s+/g, ''), { width: 200 });
  qrContainer.appendChild(canvas);

  // Copy button handler
  document.getElementById('safety-copy-btn')!.onclick = () => {
    navigator.clipboard.writeText(fingerprint.replace(/\n/g, ' ').trim());
    showToast('Safety number copied', 'success');
  };

  // Verify button handler
  document.getElementById('safety-verify-btn')!.onclick = async () => {
    if (!currentChat) return;
    await put(STORES.VERIFICATION, currentChat, {
      username: currentChat,
      verified: true,
      verifiedAt: new Date().toISOString(),
    });
    showToast('Contact verified', 'success');
  };

  const modal = document.getElementById('safety-modal')!;
  modal.classList.remove('hidden');
}

function compareBytes(a: Uint8Array, b: Uint8Array): number {
  for (let i = 0; i < Math.min(a.length, b.length); i++) {
    if (a[i] !== b[i]) return a[i]! - b[i]!;
  }
  return a.length - b.length;
}

export function getCurrentChat(): string | null {
  return currentChat;
}
