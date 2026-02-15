import { api, setToken, getToken, setCurrentUser } from './api.js';
import { connect, disconnect, on } from './ws.js';
import { initAuth, showAuth, hideAuth } from './ui/auth.js';
import { initContacts, loadContacts, addContact, selectContact, getActiveContact, incrementUnread, setUserOnline, setUserOffline, setOnlineUsers } from './ui/contacts.js';
import { initChat, openChat, handleIncomingMessage, showTypingIndicator, handleDelivered, handleReadReceipt, handleDisappearingTimerChange, updateChatStatus, getCurrentChat, addSystemMessage } from './ui/chat.js';
import { showToast, showDesktopNotification, getNotificationsEnabled } from './ui/notifications.js';
import { initSettings } from './ui/settings.js';
import { getStore, resetStore } from './signal/client.js';
import { ab2b64, onIdentityKeyChange } from './signal/store.js';
import { generateAndStoreKeys, generateMorePreKeys, rotateSignedPreKeyIfNeeded } from './signal/keys.js';
import { clearAll, initEncryption, clearEncryptionKey } from './storage/indexeddb.js';
import { WS_MSG_TYPE } from '../../shared/constants.js';

async function init() {
  initAuth(onAuthSuccess);
  initContacts(onContactSelected);
  initChat();
  initSettings(onAccountDeleted);

  document.getElementById('logout-btn').addEventListener('click', logout);

  // Initialize notification toggle state
  getNotificationsEnabled();

  // Check for existing session - requires re-login to derive encryption key
  showAuth();
}

async function onAuthSuccess(user, isNewRegistration, password) {
  try {
    // Derive storage encryption key from password
    await initEncryption(password, user.username);

    await enterChat(user, isNewRegistration);
  } catch (err) {
    showToast('Setup failed: ' + err.message, 'error');
    console.error('Auth success handler error:', err);
  }
}

async function enterChat(user, isNewRegistration) {
  const store = getStore();

  if (isNewRegistration) {
    showToast('Generating encryption keys...', 'info');
    const bundle = await generateAndStoreKeys(store);
    await api.uploadBundle(bundle);
    showToast('Keys generated and uploaded', 'success');
  } else {
    const idKey = await store.getIdentityKeyPair();
    if (!idKey) {
      showToast('Generating encryption keys...', 'info');
      const bundle = await generateAndStoreKeys(store);
      await api.uploadBundle(bundle);
      showToast('Keys regenerated', 'success');
    }
  }

  hideAuth();
  document.getElementById('current-user').textContent = user.username;

  // CRITICAL: Warn user when a contact's identity key changes (MITM detection)
  onIdentityKeyChange((username) => {
    addSystemMessage(username,
      'WARNING: ' + username + '\'s safety number has changed. ' +
      'This could mean they reinstalled the app, or someone may be ' +
      'intercepting your messages. Verify the safety number before continuing.');
    showToast('Security alert: ' + username + '\'s identity key changed!', 'error');
  });

  await loadContacts();

  connect();
  setupWSHandlers();

  // Fetch pending messages
  try {
    const pending = await api.getPendingMessages();
    for (const msg of pending) {
      addContact({ id: msg.fromId, username: msg.from });
      // Pass dbId through so handleIncomingMessage can ACK via WebSocket
      await handleIncomingMessage(msg);
      if (getActiveContact() !== msg.from) {
        incrementUnread(msg.from);
      }
    }
  } catch (err) {
    console.error('Failed to fetch pending messages:', err);
  }

  // Check pre-key count and rotate signed pre-key if needed
  try {
    const { count } = await api.getKeyCount();
    if (count < 10) {
      await replenishKeys();
    }
  } catch (err) {
    console.error('Key count check failed:', err);
  }

  try {
    const rotatedSPK = await rotateSignedPreKeyIfNeeded(store);
    if (rotatedSPK) {
      // Re-upload bundle with new signed pre-key
      const regId = await store.getLocalRegistrationId();
      const idKey = await store.getIdentityKeyPair();
      await api.uploadBundle({
        registrationId: regId,
        identityKey: ab2b64(idKey.pubKey),
        signedPreKey: rotatedSPK,
        preKeys: [],
      });
    }
  } catch (err) {
    console.error('Signed pre-key rotation failed:', err);
  }
}

function setupWSHandlers() {
  on(WS_MSG_TYPE.MESSAGE, async (data) => {
    addContact({ id: data.fromId, username: data.from });

    const result = await handleIncomingMessage(data);

    if (getActiveContact() !== data.from) {
      incrementUnread(data.from);
      if (result.text) {
        showToast(`${data.from}: ${result.text.slice(0, 50)}`, 'info');
      }
    }

    // Desktop notification for messages from non-active contacts or when unfocused
    if (result.text) {
      showDesktopNotification(data.from, result.text);
    }
  });

  on(WS_MSG_TYPE.DELIVERED, (data) => {
    handleDelivered(data);
  });

  on(WS_MSG_TYPE.READ_RECEIPT, (data) => {
    handleReadReceipt(data);
  });

  on(WS_MSG_TYPE.TYPING, (data) => {
    showTypingIndicator(data.from, data.isTyping);
  });

  on(WS_MSG_TYPE.PRESENCE, (data) => {
    if (data.onlineUserIds) {
      // Initial presence list
      setOnlineUsers(data.onlineUserIds);
    } else if (data.userId !== undefined) {
      // Individual presence update
      if (data.online) {
        setUserOnline(data.userId);
      } else {
        setUserOffline(data.userId);
      }
    }
    // Update chat header if a contact's status changed
    if (data.username) {
      updateChatStatus(data.username);
    }
  });

  on(WS_MSG_TYPE.DISAPPEARING_TIMER, (data) => {
    handleDisappearingTimerChange(data);
  });

  on(WS_MSG_TYPE.PREKEY_LOW, async () => {
    await replenishKeys();
  });

  on('open', () => {
    // Connection established
  });

  on('close', () => {
    // Will auto-reconnect with exponential backoff
  });
}

async function replenishKeys() {
  try {
    const store = getStore();
    const newKeys = await generateMorePreKeys(store);
    await api.replenishKeys(newKeys);
  } catch (err) {
    console.error('Failed to replenish keys:', err);
  }
}

function onContactSelected(username) {
  openChat(username);
}

function logout() {
  disconnect();
  setToken(null);
  setCurrentUser(null);
  resetStore();
  clearEncryptionKey();
  clearAll();
  showAuth();
  document.getElementById('chat-view').classList.add('hidden');
  document.getElementById('auth-view').classList.remove('hidden');
}

function onAccountDeleted() {
  logout();
}

init().catch((err) => {
  console.error('Init error:', err);
});
