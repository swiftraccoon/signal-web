import {
  SessionBuilder,
  SessionCipher,
  SignalProtocolAddress,
} from '@privacyresearch/libsignal-protocol-typescript';
import { SignalProtocolStore, b642ab, zeroArrayBuffer } from './store';
import { pad, unpad } from './padding';
import { storeKeyLogProof } from './keyLogGossip';
import { api } from '../api';

const DEVICE_ID = 1;

let store: SignalProtocolStore | null = null;

// Per-user session establishment locks to prevent race conditions
const sessionLocks = new Map<string, Promise<void>>();

export function getStore(): SignalProtocolStore {
  if (!store) store = new SignalProtocolStore();
  return store;
}

export function resetStore(): void {
  store = null;
}

function getAddress(username: string): SignalProtocolAddress {
  return new SignalProtocolAddress(username, DEVICE_ID);
}

interface DeviceBundle {
  registrationId: number;
  identityKey: ArrayBuffer;
  signedPreKey: {
    keyId: number;
    publicKey: ArrayBuffer;
    signature: ArrayBuffer;
  };
  preKey?: {
    keyId: number;
    publicKey: ArrayBuffer;
  };
}

async function ensureSession(username: string, userId: number): Promise<void> {
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
  let resolveLock!: () => void;
  const lockPromise = new Promise<void>(r => { resolveLock = r; });
  sessionLocks.set(username, lockPromise);

  try {
    // H3: Re-check after acquiring lock — another waiter may have established the session
    const recheckCipher = new SessionCipher(s, address);
    if (await recheckCipher.hasOpenSession()) {
      return;
    }

    // Fetch pre-key bundle from server
    const bundle = await api.getBundle(userId);

    const deviceBundle: DeviceBundle = {
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

    // Cache key transparency proof for gossip verification
    if (bundle.keyLogProof) {
      storeKeyLogProof(userId, bundle.keyLogProof);
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
function binaryStringToBase64(binaryStr: string): string {
  return btoa(binaryStr);
}

function base64ToBinaryString(b64: string): string {
  return atob(b64);
}

export interface SignalEncryptedMessage {
  type: number;
  body: string;
}

export async function encryptMessage(username: string, userId: number, plaintext: string): Promise<SignalEncryptedMessage> {
  await ensureSession(username, userId);

  const address = getAddress(username);
  const cipher = new SessionCipher(getStore(), address);

  const textBytes = new TextEncoder().encode(plaintext);
  const padded = pad(textBytes);
  const result = await cipher.encrypt(padded.buffer as ArrayBuffer);

  // H7: Zero the plaintext and padded buffers after encryption
  zeroArrayBuffer(textBytes.buffer as ArrayBuffer);
  zeroArrayBuffer(padded.buffer as ArrayBuffer);

  // Body from encrypt is a binary string; base64 encode for safe JSON transport
  return {
    type: result.type,
    body: binaryStringToBase64(result.body!),
  };
}

export async function decryptMessage(senderUsername: string, encryptedMessage: SignalEncryptedMessage): Promise<string> {
  const address = getAddress(senderUsername);
  const cipher = new SessionCipher(getStore(), address);

  // Decode base64 back to binary string for the library
  const binaryBody = base64ToBinaryString(encryptedMessage.body);
  let plainBuffer: ArrayBuffer;

  if (encryptedMessage.type === 3) {
    // PreKeyWhisperMessage (type 3 in this library)
    plainBuffer = await cipher.decryptPreKeyWhisperMessage(binaryBody, 'binary');
  } else if (encryptedMessage.type === 1) {
    // WhisperMessage (type 1 in this library)
    plainBuffer = await cipher.decryptWhisperMessage(binaryBody, 'binary');
  } else {
    throw new Error(`Unknown message type: ${encryptedMessage.type}`);
  }

  const paddedBytes = new Uint8Array(plainBuffer);
  const originalBytes = unpad(paddedBytes);
  const text = new TextDecoder().decode(originalBytes);
  // H7: Zero buffers after decoding
  zeroArrayBuffer(plainBuffer);
  zeroArrayBuffer(originalBytes.buffer as ArrayBuffer);
  return text;
}
