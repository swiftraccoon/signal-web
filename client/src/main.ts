import { api, setToken, setCurrentUser } from './api';
import { connect, disconnect, on } from './ws';
import { initAuth, showAuth, hideAuth } from './ui/auth';
import { initContacts, loadContacts, addContact, getActiveContact, incrementUnread } from './ui/contacts';
import { initChat, openChat, handleIncomingMessage, handleDelivered, handleDisappearingTimerChange, addSystemMessage } from './ui/chat';
import { showToast, showDesktopNotification, getNotificationsEnabled } from './ui/notifications';
import { initSettings } from './ui/settings';
import { getStore, resetStore } from './signal/client';
import { ab2b64, onIdentityKeyChange } from './signal/store';
import { generateAndStoreKeys, generateMorePreKeys, rotateSignedPreKeyIfNeeded } from './signal/keys';
import { unsealMessage, verifySenderCertificate, setServerPublicKey } from './signal/sealed';
import { clearSenderCertCache } from './signal/senderCertCache';
import { setOwnKeyLogHash, verifyGossipHash, clearKeyLogGossip } from './signal/keyLogGossip';
import { clearAll, initEncryption, clearEncryptionKey, upgradeIterationsIfNeeded, upgradeToArgon2idIfNeeded, remove, get, put, STORES } from './storage/indexeddb';
import { showOnboardingIfNew } from './ui/onboarding';
import { WS_MSG_TYPE } from '../../shared/constants';
import type { ApiUser, WsServerChatMessage, WsServerSealedMessage, WsServerDeliveredMessage, WsServerDisappearingTimerMessage, WsServerErrorMessage } from '../../shared/types';

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

function init(): void {
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

    // Upgrade to Argon2id if WASM is available (async, fire-and-forget)
    void upgradeToArgon2idIfNeeded(password, user.username);

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

  // Fetch our own key log hash for gossip
  try {
    const keyLog = await api.getKeyLog(user.id);
    if (keyLog.length > 0) {
      setOwnKeyLogHash(user.id, keyLog[keyLog.length - 1]!.entryHash);
    }
  } catch {
    // Non-critical — gossip will just be unavailable
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

  // Fetch server's Ed25519 public key for sender certificate verification
  // TOFU: Pin server sealed sender key on first use
  try {
    const { publicKey } = await api.getServerKey();

    const pinnedKey = await get(STORES.CRYPTO_PARAMS, 'pinned_server_key') as string | undefined;
    if (!pinnedKey) {
      // First use — pin the key
      await put(STORES.CRYPTO_PARAMS, 'pinned_server_key', publicKey);
    } else if (pinnedKey !== publicKey) {
      // Key changed — potential MITM, warn the user
      showServerKeyChangeWarning(pinnedKey, publicKey);
    }

    await setServerPublicKey(publicKey);
  } catch (err) {
    console.error('Failed to fetch server public key:', err);
  }

  void connect();
  setupWSHandlers();

  // Fetch pending messages (regular + sealed)
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

  try {
    const pendingSealed = await api.getPendingSealedMessages();
    for (const sealed of pendingSealed) {
      await handleSealedIncoming(sealed.envelope, sealed.timestamp, sealed.dbId);
    }
  } catch (err) {
    console.error('Failed to fetch pending sealed messages:', err);
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

  // Show onboarding tour for first-time users
  void showOnboardingIfNew();
}

async function handleSealedIncoming(
  envelope: WsServerSealedMessage['envelope'],
  timestamp: string,
  dbId: number,
): Promise<void> {
  try {
    const store = getStore();
    const identityKeyPair = await store.getIdentityKeyPair();
    if (!identityKeyPair) {
      console.error('Cannot unseal: no identity key pair');
      return;
    }

    const unsealed = await unsealMessage(envelope, identityKeyPair.privKey);
    const { senderCert, message } = unsealed;

    // Verify the sender certificate was signed by our server
    const certPayload = await verifySenderCertificate(senderCert);
    if (!certPayload) {
      console.error('Sealed message: invalid or expired sender certificate');
      return;
    }

    // IMP-7: Cross-check cert identity key against stored Signal session identity key.
    // Warn but don't reject — key changes can be legitimate (re-registration, key rotation).
    const storedIdentityKey = await store.loadIdentityKey(`${certPayload.username}.1`);
    if (storedIdentityKey) {
      const storedB64 = ab2b64(storedIdentityKey);
      if (storedB64 !== certPayload.identityKey) {
        console.warn('Sealed message: cert identity key differs from stored session key for', certPayload.username);
        addSystemMessage(certPayload.username,
          'WARNING: Sender certificate identity key does not match known key for ' + certPayload.username +
          '. Their key may have changed. Verify safety numbers.');
        showToast('Security alert: identity key mismatch for ' + certPayload.username, 'error');
      }
    }

    // Gossip verification: check sender's key log hash for split-view attacks
    if (unsealed.gossipHash) {
      const gossipResult = await verifyGossipHash(certPayload.userId, unsealed.gossipHash);
      if (!gossipResult.consistent) {
        console.error('KEY TRANSPARENCY WARNING:', gossipResult.details);
        addSystemMessage(certPayload.username,
          'WARNING: Key transparency check failed for ' + certPayload.username +
          '. The server may be presenting different key histories. Verify safety numbers.');
        showToast('Security alert: key transparency mismatch for ' + certPayload.username, 'error');
      }
    }

    // Process the inner Signal ciphertext through normal message handling
    addContact({ id: certPayload.userId, username: certPayload.username });
    const result = await handleIncomingMessage({
      from: certPayload.username,
      fromId: certPayload.userId,
      message,
      timestamp,
      dbId,
    });

    if (getActiveContact() !== certPayload.username) {
      incrementUnread(certPayload.username);
      if (result.text) {
        showToast(`${certPayload.username}: ${result.text.slice(0, 50)}`, 'info');
      }
    }
    if (result.text) {
      showDesktopNotification(certPayload.username, result.text);
    }
  } catch (err) {
    console.error('Sealed message processing error:', err);
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

  on(WS_MSG_TYPE.SEALED_MESSAGE, async (raw) => {
    const data = raw as WsServerSealedMessage;
    await handleSealedIncoming(data.envelope, data.timestamp, data.dbId);
  });

  on(WS_MSG_TYPE.DELIVERED, (raw) => {
    void handleDelivered(raw as WsServerDeliveredMessage);
  });

  on(WS_MSG_TYPE.DISAPPEARING_TIMER, (raw) => {
    handleDisappearingTimerChange(raw as WsServerDisappearingTimerMessage);
  });

  on(WS_MSG_TYPE.PREKEY_LOW, async () => {
    await replenishKeys();
  });

  on(WS_MSG_TYPE.PREKEY_STALE, async () => {
    try {
      const store = getStore();
      const rotatedSPK = await rotateSignedPreKeyIfNeeded(store);
      if (rotatedSPK) {
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
      console.error('Signed pre-key auto-rotation failed:', err);
    }
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
  void openChat(username);
}

function logout(): void {
  disconnect();
  setToken(null);
  setCurrentUser(null);
  resetStore();
  clearSenderCertCache();
  clearKeyLogGossip();
  clearEncryptionKey();
  void clearAll();
  showAuth();
  document.getElementById('chat-view')!.classList.add('hidden');
  document.getElementById('auth-view')!.classList.remove('hidden');
}

function onAccountDeleted(): void {
  logout();
}

function showServerKeyChangeWarning(oldKey: string, newKey: string): void {
  const modal = document.getElementById('server-key-change-modal')!;
  const oldKeySpan = document.getElementById('server-key-old')!;
  const newKeySpan = document.getElementById('server-key-new')!;

  oldKeySpan.textContent = oldKey.slice(0, 16) + '...';
  newKeySpan.textContent = newKey.slice(0, 16) + '...';
  modal.classList.remove('hidden');

  document.getElementById('server-key-accept-btn')!.onclick = async () => {
    await put(STORES.CRYPTO_PARAMS, 'pinned_server_key', newKey);
    modal.classList.add('hidden');
  };

  document.getElementById('server-key-reject-btn')!.onclick = () => {
    modal.classList.add('hidden');
    window.location.reload();
  };
}

init();
