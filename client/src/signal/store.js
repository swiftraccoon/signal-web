import { Direction } from '@privacyresearch/libsignal-protocol-typescript';
import { STORES, get, put, remove } from '../storage/indexeddb.js';

// Utility to convert ArrayBuffer to/from base64 for storage
// Uses chunked processing to avoid stack overflow on large buffers
function ab2b64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function b642ab(base64) {
  const bin = atob(base64);
  const buf = new ArrayBuffer(bin.length);
  const arr = new Uint8Array(buf);
  for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
  return buf;
}

function serializeKeyPair(kp) {
  return { pubKey: ab2b64(kp.pubKey), privKey: ab2b64(kp.privKey) };
}

function deserializeKeyPair(kp) {
  if (!kp) return undefined;
  return { pubKey: b642ab(kp.pubKey), privKey: b642ab(kp.privKey) };
}

export { ab2b64, b642ab };

// Identity key change event system
const identityKeyChangeListeners = new Set();

export function onIdentityKeyChange(fn) {
  identityKeyChangeListeners.add(fn);
}

export function offIdentityKeyChange(fn) {
  identityKeyChangeListeners.delete(fn);
}

export class SignalProtocolStore {
  async getIdentityKeyPair() {
    const kp = await get(STORES.IDENTITY_KEY_PAIR, 'identityKey');
    return deserializeKeyPair(kp);
  }

  async getLocalRegistrationId() {
    return await get(STORES.REGISTRATION_ID, 'registrationId');
  }

  async isTrustedIdentity(identifier, identityKey, _direction) {
    const stored = await get(STORES.IDENTITY_KEYS, identifier);
    if (!stored) return true; // Trust on first use (TOFU)
    // Constant-time comparison to prevent timing side channel
    const incoming = ab2b64(identityKey);
    if (incoming.length !== stored.length) return false;
    let diff = 0;
    for (let i = 0; i < incoming.length; i++) {
      diff |= incoming.charCodeAt(i) ^ stored.charCodeAt(i);
    }
    return diff === 0;
  }

  async saveIdentity(encodedAddress, publicKey) {
    const existing = await get(STORES.IDENTITY_KEYS, encodedAddress);
    const b64 = ab2b64(publicKey);
    const changed = existing !== undefined && existing !== b64;
    if (changed) {
      // Archive the old identity for key change detection
      await put(STORES.IDENTITY_KEYS, `${encodedAddress}:prev`, existing);
      // Notify listeners about identity key change (MITM detection)
      const username = encodedAddress.split('.')[0];
      for (const fn of identityKeyChangeListeners) {
        try { fn(username); } catch (e) { /* listener error must not break protocol */ }
      }
    }
    await put(STORES.IDENTITY_KEYS, encodedAddress, b64);
    return changed; // returns true if key changed
  }

  async loadIdentityKey(identifier) {
    const b64 = await get(STORES.IDENTITY_KEYS, identifier);
    if (!b64) return undefined;
    return b642ab(b64);
  }

  async loadPreKey(keyId) {
    const kp = await get(STORES.PRE_KEYS, String(keyId));
    return deserializeKeyPair(kp);
  }

  async storePreKey(keyId, keyPair) {
    await put(STORES.PRE_KEYS, String(keyId), serializeKeyPair(keyPair));
  }

  async removePreKey(keyId) {
    await remove(STORES.PRE_KEYS, String(keyId));
  }

  async loadSignedPreKey(keyId) {
    const kp = await get(STORES.SIGNED_PRE_KEYS, String(keyId));
    return deserializeKeyPair(kp);
  }

  async storeSignedPreKey(keyId, keyPair) {
    await put(STORES.SIGNED_PRE_KEYS, String(keyId), serializeKeyPair(keyPair));
  }

  async removeSignedPreKey(keyId) {
    await remove(STORES.SIGNED_PRE_KEYS, String(keyId));
  }

  async loadSession(encodedAddress) {
    return await get(STORES.SESSIONS, encodedAddress);
  }

  async storeSession(encodedAddress, record) {
    await put(STORES.SESSIONS, encodedAddress, record);
  }

  // Helper: store identity key pair during registration
  async saveIdentityKeyPair(keyPair) {
    await put(STORES.IDENTITY_KEY_PAIR, 'identityKey', serializeKeyPair(keyPair));
  }

  async saveLocalRegistrationId(regId) {
    await put(STORES.REGISTRATION_ID, 'registrationId', regId);
  }
}
