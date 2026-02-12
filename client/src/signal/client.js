import {
  SessionBuilder,
  SessionCipher,
  SignalProtocolAddress,
} from '@privacyresearch/libsignal-protocol-typescript';
import { SignalProtocolStore, ab2b64, b642ab } from './store.js';
import { api } from '../api.js';

const DEVICE_ID = 1;

let store = null;

// Per-user session establishment locks to prevent race conditions
const sessionLocks = new Map(); // username -> Promise

export function getStore() {
  if (!store) store = new SignalProtocolStore();
  return store;
}

export function resetStore() {
  store = null;
}

function getAddress(username) {
  return new SignalProtocolAddress(username, DEVICE_ID);
}

async function ensureSession(username, userId) {
  // Serialize session establishment per-user to prevent race conditions
  while (sessionLocks.has(username)) {
    await sessionLocks.get(username);
  }

  const address = getAddress(username);
  const s = getStore();
  const cipher = new SessionCipher(s, address);

  if (await cipher.hasOpenSession()) {
    return; // session already exists
  }

  // Create lock for this user's session establishment
  let resolveLock;
  const lockPromise = new Promise(r => { resolveLock = r; });
  sessionLocks.set(username, lockPromise);

  try {
    // Fetch pre-key bundle from server
    const bundle = await api.getBundle(userId);

    const deviceBundle = {
      registrationId: bundle.registrationId,
      identityKey: b642ab(bundle.identityKey),
      signedPreKey: {
        keyId: bundle.signedPreKey.keyId,
        publicKey: b642ab(bundle.signedPreKey.publicKey),
        signature: b642ab(bundle.signedPreKey.signature),
      },
    };

    if (bundle.preKey) {
      deviceBundle.preKey = {
        keyId: bundle.preKey.keyId,
        publicKey: b642ab(bundle.preKey.publicKey),
      };
    }

    const builder = new SessionBuilder(s, address);
    await builder.processPreKey(deviceBundle);
  } finally {
    sessionLocks.delete(username);
    resolveLock();
  }
}

// The Signal library returns binary strings (each char 0-255).
// Base64 encode for safe JSON transport over WebSocket.
function binaryStringToBase64(binaryStr) {
  return btoa(binaryStr);
}

function base64ToBinaryString(b64) {
  return atob(b64);
}

export async function encryptMessage(username, userId, plaintext) {
  await ensureSession(username, userId);

  const address = getAddress(username);
  const cipher = new SessionCipher(getStore(), address);

  const textBytes = new TextEncoder().encode(plaintext);
  const result = await cipher.encrypt(textBytes.buffer);

  // Body from encrypt is a binary string; base64 encode for safe JSON transport
  return {
    type: result.type,
    body: binaryStringToBase64(result.body),
  };
}

export async function decryptMessage(senderUsername, encryptedMessage) {
  const address = getAddress(senderUsername);
  const cipher = new SessionCipher(getStore(), address);

  // Decode base64 back to binary string for the library
  const binaryBody = base64ToBinaryString(encryptedMessage.body);
  let plainBuffer;

  if (encryptedMessage.type === 3) {
    // PreKeyWhisperMessage (type 3 in this library)
    plainBuffer = await cipher.decryptPreKeyWhisperMessage(binaryBody, 'binary');
  } else if (encryptedMessage.type === 1) {
    // WhisperMessage (type 1 in this library)
    plainBuffer = await cipher.decryptWhisperMessage(binaryBody, 'binary');
  } else {
    throw new Error(`Unknown message type: ${encryptedMessage.type}`);
  }

  return new TextDecoder().decode(plainBuffer);
}
