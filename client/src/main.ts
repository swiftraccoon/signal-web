import { api, setToken, setRefreshToken, setCurrentUser } from './api';
import { connect, disconnect, on } from './ws';
import { initAuth, showAuth, hideAuth } from './ui/auth';
import { initContacts, loadContacts, addContact, getActiveContact, incrementUnread, setUserOnline, setUserOffline, setOnlineUsers } from './ui/contacts';
import { initChat, openChat, handleIncomingMessage, showTypingIndicator, handleDelivered, handleReadReceipt, handleDisappearingTimerChange, updateChatStatus, addSystemMessage } from './ui/chat';
import { showToast, showDesktopNotification, getNotificationsEnabled } from './ui/notifications';
import { initSettings } from './ui/settings';
import { getStore, resetStore } from './signal/client';
import { ab2b64, onIdentityKeyChange } from './signal/store';
import { generateAndStoreKeys, generateMorePreKeys, rotateSignedPreKeyIfNeeded } from './signal/keys';
import { clearAll, initEncryption, clearEncryptionKey, upgradeIterationsIfNeeded, remove, STORES } from './storage/indexeddb';
import { WS_MSG_TYPE } from '../../shared/constants';
import type { ApiUser, WsServerChatMessage, WsServerDeliveredMessage, WsServerReadReceiptMessage, WsServerPresenceMessage, WsServerDisappearingTimerMessage, WsServerErrorMessage } from '../../shared/types';

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

async function init(): Promise<void> {
  initAuth(onAuthSuccess);
  initContacts(onContactSelected);
  initChat();
  initSettings(onAccountDeleted);

  document.getElementById('logout-btn')!.addEventListener('click', logout);

  // Initialize notification toggle state
  getNotificationsEnabled();

  // Check for existing session - requires re-login to derive encryption key
  showAuth();
}

async function onAuthSuccess(user: ApiUser, isNewRegistration: boolean, password: string): Promise<void> {
  const authBtn = document.getElementById('auth-submit') as HTMLButtonElement;
  const originalText = authBtn.textContent || 'Log In';
  setLoading(authBtn, true, originalText);
  try {
    // Derive storage encryption key from password
    await initEncryption(password, user.username);

    // M5: Upgrade PBKDF2 iteration count for existing users (transparent re-encryption)
    await upgradeIterationsIfNeeded(password, user.username);

    await enterChat(user, isNewRegistration);
  } catch (err) {
    console.error('Auth success handler error:', err);
    const errorMsg = (err as Error).message || '';
    let friendlyMsg = 'Setup failed. Please try again.';
    if (errorMsg.includes('key') || errorMsg.includes('crypto') || errorMsg.includes('encrypt')) {
      friendlyMsg = 'Encryption key setup failed — try clearing browser data.';
    } else if (errorMsg.includes('network') || errorMsg.includes('fetch')) {
      friendlyMsg = "Can't reach the server — check your connection.";
    }
    showToast(friendlyMsg, 'error');
  } finally {
    setLoading(authBtn, false, originalText);
  }
}

async function enterChat(user: ApiUser, isNewRegistration: boolean): Promise<void> {
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
  document.getElementById('current-user')!.textContent = user.username;

  // CRITICAL: Warn user when a contact's identity key changes (MITM detection)
  onIdentityKeyChange(async (username: string) => {
    addSystemMessage(username,
      'WARNING: ' + username + '\'s safety number has changed. ' +
      'This could mean they reinstalled the app, or someone may be ' +
      'intercepting your messages. Verify the safety number before continuing.');
    showToast('Security alert: ' + username + '\'s identity key changed!', 'error');

    // Clear their verification status
    await remove(STORES.VERIFICATION, username);

    // Show identity change blocking modal
    const modal = document.getElementById('identity-change-modal')!;
    const userSpan = document.getElementById('identity-change-user')!;
    userSpan.textContent = username;
    modal.classList.remove('hidden');

    document.getElementById('identity-accept-btn')!.onclick = () => {
      modal.classList.add('hidden');
    };

    document.getElementById('identity-block-btn')!.onclick = () => {
      modal.classList.add('hidden');
      showToast('Contact blocked', 'info');
    };
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
        registrationId: regId!,
        identityKey: ab2b64(idKey!.pubKey),
        signedPreKey: rotatedSPK,
        preKeys: [],
      });
    }
  } catch (err) {
    console.error('Signed pre-key rotation failed:', err);
  }
}

function setupWSHandlers(): void {
  on(WS_MSG_TYPE.MESSAGE, async (raw) => {
    const data = raw as WsServerChatMessage;
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

  on(WS_MSG_TYPE.DELIVERED, (raw) => {
    handleDelivered(raw as WsServerDeliveredMessage);
  });

  on(WS_MSG_TYPE.READ_RECEIPT, (raw) => {
    handleReadReceipt(raw as WsServerReadReceiptMessage);
  });

  on(WS_MSG_TYPE.TYPING, (raw) => {
    const data = raw as { from: string; isTyping: boolean };
    showTypingIndicator(data.from, data.isTyping);
  });

  on(WS_MSG_TYPE.PRESENCE, (raw) => {
    const data = raw as WsServerPresenceMessage;
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

  on(WS_MSG_TYPE.DISAPPEARING_TIMER, (raw) => {
    handleDisappearingTimerChange(raw as WsServerDisappearingTimerMessage);
  });

  on(WS_MSG_TYPE.PREKEY_LOW, async () => {
    await replenishKeys();
  });

  on(WS_MSG_TYPE.ERROR, (raw) => {
    const data = raw as WsServerErrorMessage;
    const friendlyMessages: Record<string, string> = {
      'Invalid recipient': 'That user does not exist.',
      'Message too large': 'Your message is too long.',
      'Rate limit exceeded': 'Slow down! You\'re sending too quickly.',
      'Recipient not found': 'That user could not be found.',
    };
    const msg = friendlyMessages[data.message] || data.message;
    showToast(msg, 'error');
  });

  on('open', () => {
    // Connection established
  });

  on('close', () => {
    // Will auto-reconnect with exponential backoff
  });
}

async function replenishKeys(): Promise<void> {
  try {
    const store = getStore();
    const newKeys = await generateMorePreKeys(store);
    await api.replenishKeys(newKeys);
  } catch (err) {
    console.error('Failed to replenish keys:', err);
  }
}

function onContactSelected(username: string): void {
  openChat(username);
}

function logout(): void {
  disconnect();
  setToken(null);
  setRefreshToken(null);
  setCurrentUser(null);
  resetStore();
  clearEncryptionKey();
  clearAll();
  showAuth();
  document.getElementById('chat-view')!.classList.add('hidden');
  document.getElementById('auth-view')!.classList.remove('hidden');
}

function onAccountDeleted(): void {
  logout();
}

init().catch((err) => {
  console.error('Init error:', err);
});
