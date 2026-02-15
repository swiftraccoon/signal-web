import { Direction } from '@privacyresearch/libsignal-protocol-typescript';
import { STORES, get, put, remove } from '../storage/indexeddb';

interface KeyPairType {
  pubKey: ArrayBuffer;
  privKey: ArrayBuffer;
}

interface SerializedKeyPair {
  pubKey: string;
  privKey: string;
}

// H7: Best-effort memory zeroing for sensitive ArrayBuffers
function zeroArrayBuffer(buffer: ArrayBuffer): void {
  new Uint8Array(buffer).fill(0);
}

// Utility to convert ArrayBuffer to/from base64 for storage
function ab2b64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]!);
  }
  return btoa(binary);
}

function b642ab(base64: string): ArrayBuffer {
  const bin = atob(base64);
  const buf = new ArrayBuffer(bin.length);
  const arr = new Uint8Array(buf);
  for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
  return buf;
}

function serializeKeyPair(kp: KeyPairType): SerializedKeyPair {
  const serialized = { pubKey: ab2b64(kp.pubKey), privKey: ab2b64(kp.privKey) };
  // H7: Zero the private key after serialization
  zeroArrayBuffer(kp.privKey);
  return serialized;
}

function deserializeKeyPair(kp: unknown): KeyPairType | undefined {
  if (!kp) return undefined;
  const skp = kp as SerializedKeyPair;
  return { pubKey: b642ab(skp.pubKey), privKey: b642ab(skp.privKey) };
}

export { ab2b64, b642ab, zeroArrayBuffer };

// Identity key change event system
type IdentityKeyChangeListener = (username: string) => void;
const identityKeyChangeListeners = new Set<IdentityKeyChangeListener>();

export function onIdentityKeyChange(fn: IdentityKeyChangeListener): void {
  identityKeyChangeListeners.add(fn);
}

export function offIdentityKeyChange(fn: IdentityKeyChangeListener): void {
  identityKeyChangeListeners.delete(fn);
}

// H2: Per-address identity lock to prevent TOCTOU race on key change detection
const identityLocks = new Map<string, Promise<void>>();

export class SignalProtocolStore {
  async getIdentityKeyPair(): Promise<KeyPairType | undefined> {
    const kp = await get(STORES.IDENTITY_KEY_PAIR, 'identityKey');
    return deserializeKeyPair(kp);
  }

  async getLocalRegistrationId(): Promise<number | undefined> {
    return await get(STORES.REGISTRATION_ID, 'registrationId') as number | undefined;
  }

  async isTrustedIdentity(identifier: string, identityKey: ArrayBuffer, _direction: Direction): Promise<boolean> {
    const stored = await get(STORES.IDENTITY_KEYS, identifier) as string | undefined;
    if (!stored) return true; // Trust on first use (TOFU)
    // Constant-time comparison to prevent timing side channel
    // Note: JS JIT may optimize away constant-time property; this is best-effort
    const incoming = ab2b64(identityKey);
    if (incoming.length !== stored.length) return false;
    let diff = 0;
    for (let i = 0; i < incoming.length; i++) {
      diff |= incoming.charCodeAt(i) ^ stored.charCodeAt(i);
    }
    return diff === 0;
  }

  // H2: Serialize identity key updates per-address to prevent TOCTOU race
  async saveIdentity(encodedAddress: string, publicKey: ArrayBuffer): Promise<boolean> {
    while (identityLocks.has(encodedAddress)) {
      await identityLocks.get(encodedAddress);
    }

    let resolveLock!: () => void;
    const lock = new Promise<void>(r => { resolveLock = r; });
    identityLocks.set(encodedAddress, lock);

    try {
      const existing = await get(STORES.IDENTITY_KEYS, encodedAddress) as string | undefined;
      const b64 = ab2b64(publicKey);
      const changed = existing !== undefined && existing !== b64;
      if (changed) {
        // Archive the old identity for key change detection
        await put(STORES.IDENTITY_KEYS, `${encodedAddress}:prev`, existing);
        // Notify listeners about identity key change (MITM detection)
        const username = encodedAddress.split('.')[0]!;
        for (const fn of identityKeyChangeListeners) {
          try { fn(username); } catch { /* listener error must not break protocol */ }
        }
      }
      await put(STORES.IDENTITY_KEYS, encodedAddress, b64);
      return changed;
    } finally {
      identityLocks.delete(encodedAddress);
      resolveLock();
    }
  }

  async loadIdentityKey(identifier: string): Promise<ArrayBuffer | undefined> {
    const b64 = await get(STORES.IDENTITY_KEYS, identifier) as string | undefined;
    if (!b64) return undefined;
    return b642ab(b64);
  }

  async loadPreKey(keyId: string | number): Promise<KeyPairType | undefined> {
    const kp = await get(STORES.PRE_KEYS, String(keyId));
    return deserializeKeyPair(kp);
  }

  async storePreKey(keyId: string | number, keyPair: KeyPairType): Promise<void> {
    await put(STORES.PRE_KEYS, String(keyId), serializeKeyPair(keyPair));
  }

  async removePreKey(keyId: string | number): Promise<void> {
    await remove(STORES.PRE_KEYS, String(keyId));
  }

  async loadSignedPreKey(keyId: string | number): Promise<KeyPairType | undefined> {
    const kp = await get(STORES.SIGNED_PRE_KEYS, String(keyId));
    return deserializeKeyPair(kp);
  }

  async storeSignedPreKey(keyId: string | number, keyPair: KeyPairType): Promise<void> {
    await put(STORES.SIGNED_PRE_KEYS, String(keyId), serializeKeyPair(keyPair));
  }

  async removeSignedPreKey(keyId: string | number): Promise<void> {
    await remove(STORES.SIGNED_PRE_KEYS, String(keyId));
  }

  async loadSession(encodedAddress: string): Promise<string | undefined> {
    return await get(STORES.SESSIONS, encodedAddress) as string | undefined;
  }

  async storeSession(encodedAddress: string, record: string): Promise<void> {
    await put(STORES.SESSIONS, encodedAddress, record);
  }

  // Helper: store identity key pair during registration
  async saveIdentityKeyPair(keyPair: KeyPairType): Promise<void> {
    await put(STORES.IDENTITY_KEY_PAIR, 'identityKey', serializeKeyPair(keyPair));
  }

  async saveLocalRegistrationId(regId: number): Promise<void> {
    await put(STORES.REGISTRATION_ID, 'registrationId', regId);
  }
}
