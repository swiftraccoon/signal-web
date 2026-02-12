import { STORES, get, put, putDebounced } from '../storage/indexeddb.js';
import { encryptMessage, decryptMessage } from '../signal/client.js';
import { send as wsSend } from '../ws.js';
import { getActiveContact, getContactInfo, updateLastMessage, isContactOnline } from './contacts.js';
import { showToast } from './notifications.js';
import { WS_MSG_TYPE } from '../../../shared/constants.js';

let currentChat = null; // username
let messageHistory = {}; // username -> [{text, sent, time, id, status, disappearAt}]
let disappearingTimers = {}; // username -> timer seconds (0 = off)
let disappearIntervals = {}; // username -> interval id
let renderScheduled = false; // rAF debounce flag
let messageIdLookup = new Map(); // msgId -> username for O(1) status lookups

// URL regex - matches http/https URLs
const URL_REGEX = /https?:\/\/[^\s<>"')\]]+/g;

export function initChat() {
  const form = document.getElementById('message-form');
  const input = document.getElementById('message-input');

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const text = input.value.trim();
    if (!text || !currentChat) return;

    const contact = getContactInfo(currentChat);
    if (!contact) return;

    input.value = '';
    input.disabled = true;

    try {
      const encrypted = await encryptMessage(currentChat, contact.id, text);

      const msgId = Date.now().toString(36) + Math.random().toString(36).slice(2, 6);

      wsSend({
        type: WS_MSG_TYPE.MESSAGE,
        to: currentChat,
        message: encrypted,
        id: msgId,
      });

      const msg = {
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
      updateLastMessage(currentChat, text, msg.time);
    } catch (err) {
      console.error('Encrypt/send error:', err);
      showToast('Failed to send message: ' + err.message, 'error');
    } finally {
      input.disabled = false;
      input.focus();
    }
  });

  // Typing indicator
  let typingTimeout = null;
  input.addEventListener('input', () => {
    if (!currentChat) return;
    wsSend({ type: WS_MSG_TYPE.TYPING, to: currentChat, isTyping: true });
    clearTimeout(typingTimeout);
    typingTimeout = setTimeout(() => {
      wsSend({ type: WS_MSG_TYPE.TYPING, to: currentChat, isTyping: false });
    }, 2000);
  });

  // Disappearing messages menu
  const disappearingBtn = document.getElementById('disappearing-btn');
  const disappearingMenu = document.getElementById('disappearing-menu');

  disappearingBtn.addEventListener('click', () => {
    disappearingMenu.classList.toggle('hidden');
    updateDisappearingMenuActive();
  });

  disappearingMenu.addEventListener('click', (e) => {
    const option = e.target.closest('.disappearing-option');
    if (!option) return;
    const timer = parseInt(option.dataset.timer, 10);
    setDisappearingTimer(currentChat, timer);
    disappearingMenu.classList.add('hidden');
  });

  // Close menu on outside click
  document.addEventListener('click', (e) => {
    if (!disappearingBtn.contains(e.target) && !disappearingMenu.contains(e.target)) {
      disappearingMenu.classList.add('hidden');
    }
  });

  // Safety number button
  document.getElementById('safety-number-btn').addEventListener('click', () => {
    if (currentChat) showSafetyNumber(currentChat);
  });

  // Mobile back button
  document.getElementById('chat-back-btn').addEventListener('click', () => {
    document.getElementById('sidebar').classList.remove('sidebar-hidden');
    document.getElementById('chat-active').classList.add('hidden');
    document.getElementById('chat-placeholder').classList.remove('hidden');
    currentChat = null;
  });
}

export async function openChat(username) {
  currentChat = username;

  document.getElementById('chat-placeholder').classList.add('hidden');
  document.getElementById('chat-active').classList.remove('hidden');
  document.getElementById('chat-recipient').textContent = username;
  document.getElementById('disappearing-menu').classList.add('hidden');

  // Update online status in header
  updateChatStatus(username);

  // Hide sidebar on mobile
  if (window.innerWidth <= 768) {
    document.getElementById('sidebar').classList.add('sidebar-hidden');
  }

  // Load disappearing timer setting
  const storedTimer = await get(STORES.META, `disappear:${username}`);
  disappearingTimers[username] = storedTimer || 0;
  updateDisappearingBanner(username);

  // Load message history from IndexedDB
  if (!messageHistory[username]) {
    const stored = await get(STORES.MESSAGES, username);
    messageHistory[username] = stored || [];
  }

  // Purge expired disappearing messages
  purgeExpiredMessages(username);

  renderMessages(username);
  document.getElementById('message-input').focus();

  // Send read receipts for unread messages
  sendReadReceipts(username);

  // Start disappearing message checker
  startDisappearChecker(username);
}

export async function handleIncomingMessage(data) {
  try {
    const plaintext = await decryptMessage(data.from, data.message);

    const msg = {
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
    updateLastMessage(data.from, plaintext, msg.time);

    // ACK receipt to server so it marks the message as delivered
    if (data.dbId) {
      wsSend({
        type: WS_MSG_TYPE.ACK,
        dbId: data.dbId,
        from: data.from,
        originalId: data.id,
      });
    }

    // If this chat is currently open, send read receipt immediately
    if (currentChat === data.from && document.visibilityState === 'visible') {
      wsSend({
        type: WS_MSG_TYPE.READ_RECEIPT,
        to: data.from,
        messageIds: [data.id],
      });
    }

    return { from: data.from, text: plaintext };
  } catch (err) {
    console.error('Decrypt error:', err);
    addMessage(data.from, {
      text: '[Unable to decrypt message]',
      sent: false,
      time: data.timestamp || new Date().toISOString(),
      error: true,
    });
    return { from: data.from, text: null };
  }
}

// Handle delivery confirmation from server
export function handleDelivered(data) {
  updateMessageStatus(data.id, 'delivered');
}

// Handle read receipts from contact
export function handleReadReceipt(data) {
  if (!data.messageIds || !data.from) return;
  for (const msgId of data.messageIds) {
    updateMessageStatus(msgId, 'read');
  }
}

// Handle disappearing timer change from contact
export function handleDisappearingTimerChange(data) {
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

function setDisappearingTimer(username, timer) {
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

function formatTimerLabel(seconds) {
  if (seconds === 0) return 'off';
  if (seconds < 60) return `${seconds} seconds`;
  if (seconds < 3600) return `${seconds / 60} minutes`;
  if (seconds < 86400) return `${seconds / 3600} hour${seconds >= 7200 ? 's' : ''}`;
  return `${seconds / 86400} day${seconds >= 172800 ? 's' : ''}`;
}

function updateDisappearingBanner(username) {
  const banner = document.getElementById('disappearing-banner');
  const timer = disappearingTimers[username];
  if (timer && timer > 0) {
    banner.textContent = `Disappearing messages: ${formatTimerLabel(timer)}`;
    banner.classList.remove('hidden');
  } else {
    banner.classList.add('hidden');
  }
}

function updateDisappearingMenuActive() {
  const timer = disappearingTimers[currentChat] || 0;
  const options = document.querySelectorAll('.disappearing-option');
  for (const opt of options) {
    if (parseInt(opt.dataset.timer, 10) === timer) {
      opt.classList.add('active');
    } else {
      opt.classList.remove('active');
    }
  }
}

function updateMessageStatus(msgId, status) {
  // O(1) lookup using messageIdLookup map
  const username = messageIdLookup.get(msgId);
  if (username) {
    const msgs = messageHistory[username];
    if (msgs) {
      for (const msg of msgs) {
        if (msg.id === msgId && msg.sent) {
          const order = { sent: 0, delivered: 1, read: 2 };
          if ((order[status] || 0) > (order[msg.status] || 0)) {
            msg.status = status;
            putDebounced(STORES.MESSAGES, username, messageHistory[username]);
            if (currentChat === username) scheduleRender(username);
          }
          return;
        }
      }
    }
  }
  // Fallback: linear scan if not in lookup (e.g. loaded from storage)
  for (const uname in messageHistory) {
    const msgs = messageHistory[uname];
    for (const msg of msgs) {
      if (msg.id === msgId && msg.sent) {
        const order = { sent: 0, delivered: 1, read: 2 };
        if ((order[status] || 0) > (order[msg.status] || 0)) {
          msg.status = status;
          messageIdLookup.set(msgId, uname);
          putDebounced(STORES.MESSAGES, uname, messageHistory[uname]);
          if (currentChat === uname) scheduleRender(uname);
        }
        return;
      }
    }
  }
}

function sendReadReceipts(username) {
  const msgs = messageHistory[username] || [];
  const unreadIds = msgs
    .filter(m => !m.sent && m.id && !m.readReceiptSent)
    .map(m => m.id);

  if (unreadIds.length > 0) {
    wsSend({
      type: WS_MSG_TYPE.READ_RECEIPT,
      to: username,
      messageIds: unreadIds,
    });
    for (const msg of msgs) {
      if (unreadIds.includes(msg.id)) {
        msg.readReceiptSent = true;
      }
    }
    putDebounced(STORES.MESSAGES, username, msgs);
  }
}

function addSystemMessage(username, text) {
  if (!messageHistory[username]) messageHistory[username] = [];
  messageHistory[username].push({ system: true, text, time: new Date().toISOString() });

  const history = messageHistory[username].slice(-500);
  messageHistory[username] = history;
  putDebounced(STORES.MESSAGES, username, history);

  if (currentChat === username) scheduleRender(username);
}

function addMessage(username, msg) {
  if (!messageHistory[username]) messageHistory[username] = [];
  messageHistory[username].push(msg);

  // Track in lookup map for O(1) status updates
  if (msg.id) messageIdLookup.set(msg.id, username);

  // Persist to IndexedDB (keep last 500 messages per contact)
  const history = messageHistory[username].slice(-500);
  messageHistory[username] = history;
  putDebounced(STORES.MESSAGES, username, history);

  if (currentChat === username) {
    scheduleRender(username);
  }
}

function purgeExpiredMessages(username) {
  const msgs = messageHistory[username];
  if (!msgs) return;
  const now = Date.now();
  const filtered = msgs.filter(m => !m.disappearAt || m.disappearAt > now);
  if (filtered.length !== msgs.length) {
    messageHistory[username] = filtered;
    putDebounced(STORES.MESSAGES, username, filtered);
  }
}

// rAF-debounced render to avoid redundant DOM thrashing
function scheduleRender(username) {
  if (renderScheduled) return;
  renderScheduled = true;
  requestAnimationFrame(() => {
    renderScheduled = false;
    if (currentChat === username) renderMessages(username);
  });
}

function startDisappearChecker(username) {
  // Clear any existing interval for previous chat
  for (const key in disappearIntervals) {
    clearInterval(disappearIntervals[key]);
    delete disappearIntervals[key];
  }

  if (disappearingTimers[username] && disappearingTimers[username] > 0) {
    disappearIntervals[username] = setInterval(() => {
      const before = (messageHistory[username] || []).length;
      purgeExpiredMessages(username);
      if ((messageHistory[username] || []).length !== before && currentChat === username) {
        renderMessages(username);
      }
    }, 1000);
  }
}

function renderMessages(username) {
  const container = document.getElementById('messages-container');
  while (container.firstChild) container.removeChild(container.firstChild);

  const messages = messageHistory[username] || [];
  let lastDateStr = null;

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
      statusEl.className = `message-status ${msg.status || 'sent'}`;
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
    container.appendChild(div);
  }

  container.scrollTop = container.scrollHeight;
}

function renderTextWithLinks(element, text) {
  if (!text) return;
  const matches = [...text.matchAll(URL_REGEX)];
  if (matches.length === 0) {
    element.textContent = text;
    return;
  }

  let lastIndex = 0;
  for (const match of matches) {
    // Text before the URL
    if (match.index > lastIndex) {
      element.appendChild(document.createTextNode(text.slice(lastIndex, match.index)));
    }
    // The URL itself as a safe anchor
    const a = document.createElement('a');
    a.href = match[0];
    a.textContent = match[0];
    a.target = '_blank';
    a.rel = 'noopener noreferrer';
    element.appendChild(a);
    lastIndex = match.index + match[0].length;
  }
  // Remaining text after last URL
  if (lastIndex < text.length) {
    element.appendChild(document.createTextNode(text.slice(lastIndex)));
  }
}

export function showTypingIndicator(from, isTyping) {
  if (from === currentChat) {
    const indicator = document.getElementById('typing-indicator');
    if (isTyping) {
      indicator.classList.remove('hidden');
    } else {
      indicator.classList.add('hidden');
    }
  }
}

export function updateChatStatus(username) {
  if (currentChat !== username && username !== undefined) return;
  const target = username || currentChat;
  if (!target) return;

  const statusEl = document.getElementById('chat-status');
  if (isContactOnline(target)) {
    statusEl.textContent = 'online';
    statusEl.className = 'chat-status online';
  } else {
    statusEl.textContent = 'offline';
    statusEl.className = 'chat-status';
  }
}

function formatTime(isoString) {
  try {
    const d = new Date(isoString);
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  } catch {
    return '';
  }
}

function formatDateHeader(isoString) {
  try {
    const d = new Date(isoString);
    const now = new Date();
    const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
    const msgDate = new Date(d.getFullYear(), d.getMonth(), d.getDate());
    const diff = (today - msgDate) / (1000 * 60 * 60 * 24);

    if (diff === 0) return 'Today';
    if (diff === 1) return 'Yesterday';
    if (diff < 7) return d.toLocaleDateString([], { weekday: 'long' });
    return d.toLocaleDateString([], { year: 'numeric', month: 'long', day: 'numeric' });
  } catch {
    return '';
  }
}

async function showSafetyNumber(username) {
  const { getStore } = await import('../signal/client.js');
  const { ab2b64 } = await import('../signal/store.js');

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
  async function iterativeHash(publicKey, stableIdentifier) {
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
  let combinedFingerprint;
  if (compareBytes(myFingerprint, theirFingerprint) < 0) {
    combinedFingerprint = new Uint8Array([...myFingerprint, ...theirFingerprint]);
  } else {
    combinedFingerprint = new Uint8Array([...theirFingerprint, ...myFingerprint]);
  }

  // Format as 12 groups of 5 digits (like Signal)
  const hashArray = combinedFingerprint;
  let fingerprint = '';
  for (let i = 0; i < 30; i++) {
    const val = ((hashArray[i * 2 % hashArray.length] << 8) | hashArray[(i * 2 + 1) % hashArray.length]) % 100000;
    fingerprint += val.toString().padStart(5, '0');
    if ((i + 1) % 5 === 0) fingerprint += '\n';
    else fingerprint += ' ';
  }

  const user = JSON.parse(localStorage.getItem('user'));
  document.getElementById('safety-fingerprint').textContent = fingerprint.trim();
  document.getElementById('safety-you').textContent = user.username;
  document.getElementById('safety-them').textContent = username;

  const modal = document.getElementById('safety-modal');
  modal.classList.remove('hidden');
}

function compareBytes(a, b) {
  for (let i = 0; i < Math.min(a.length, b.length); i++) {
    if (a[i] !== b[i]) return a[i] - b[i];
  }
  return a.length - b.length;
}

export function getCurrentChat() {
  return currentChat;
}
