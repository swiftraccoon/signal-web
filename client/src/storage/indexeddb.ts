import type { EncryptedValue } from '../../../shared/types';

const DB_NAME = 'signal-web';
const DB_VERSION = 4;

const STORES = {
  IDENTITY_KEY_PAIR: 'identityKeyPair',
  REGISTRATION_ID: 'registrationId',
  PRE_KEYS: 'preKeys',
  SIGNED_PRE_KEYS: 'signedPreKeys',
  SESSIONS: 'sessions',
  IDENTITY_KEYS: 'identityKeys',
  CONTACTS: 'contacts',
  MESSAGES: 'messages',
  META: 'meta',
  VERIFICATION: 'verification',
  CRYPTO_PARAMS: 'cryptoParams', // Unencrypted store for salt etc.
  MESSAGE_QUEUE: 'message_queue',
} as const;

type StoreName = (typeof STORES)[keyof typeof STORES];

// Stores whose values are encrypted at rest with the local DB key
const ENCRYPTED_STORES = new Set<string>([
  STORES.IDENTITY_KEY_PAIR,
  STORES.PRE_KEYS,
  STORES.SIGNED_PRE_KEYS,
  STORES.SESSIONS,
  STORES.IDENTITY_KEYS,
  STORES.CONTACTS,
  STORES.MESSAGES,
  STORES.META,
  STORES.REGISTRATION_ID,
  STORES.VERIFICATION,
  STORES.MESSAGE_QUEUE,
]);

let dbInstance: IDBDatabase | null = null;
let encryptionKey: CryptoKey | null = null; // CryptoKey for AES-GCM
let reencryptionInProgress = false; // Prevents concurrent re-encryption attempts

// Write batching - coalesce rapid writes to the same store+key
interface PendingWrite {
  storeName: string;
  key: string;
  value: unknown;
}
const pendingWrites = new Map<string, PendingWrite>();
let flushTimer: ReturnType<typeof setTimeout> | null = null;
const FLUSH_DELAY_MS = 100;

const PBKDF2_ITERATIONS = 600000; // OWASP 2023+ recommendation for SHA-256
const LEGACY_PBKDF2_ITERATIONS = 100000; // Previous default, kept for backwards compat

// Derive a storage encryption key from the user's password + random salt
async function deriveStorageKey(password: string, saltBytes: Uint8Array, iterations: number): Promise<CryptoKey> {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: saltBytes as BufferSource, iterations, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

// Read a value from the unencrypted CRYPTO_PARAMS store
async function readCryptoParam(db: IDBDatabase, key: string): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORES.CRYPTO_PARAMS, 'readonly');
    const req = tx.objectStore(STORES.CRYPTO_PARAMS).get(key);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

// Write a value to the unencrypted CRYPTO_PARAMS store
async function writeCryptoParam(db: IDBDatabase, key: string, value: unknown): Promise<void> {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORES.CRYPTO_PARAMS, 'readwrite');
    tx.objectStore(STORES.CRYPTO_PARAMS).put(value, key);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

// Get or create salt and iteration count (with backwards-compat for existing users)
async function getOrCreateCryptoParams(username: string): Promise<{ salt: Uint8Array; iterations: number }> {
  const db = await open();
  const saltKey = `salt:${username}`;
  const iterKey = `iterations:${username}`;

  const [existingSalt, existingIter] = await Promise.all([
    readCryptoParam(db, saltKey) as Promise<string | undefined>,
    readCryptoParam(db, iterKey) as Promise<number | undefined>,
  ]);

  if (existingSalt) {
    const salt = Uint8Array.from(atob(existingSalt), c => c.charCodeAt(0));
    // Existing users without a stored iteration count used the legacy default
    const iterations = existingIter || LEGACY_PBKDF2_ITERATIONS;
    // Persist iteration count if it wasn't stored yet (migration)
    if (!existingIter) {
      await writeCryptoParam(db, iterKey, iterations);
    }
    return { salt, iterations };
  }

  // New user: generate salt and use strong iteration count
  const salt = crypto.getRandomValues(new Uint8Array(32));
  const iterations = PBKDF2_ITERATIONS;
  await writeCryptoParam(db, saltKey, uint8ToBase64(salt));
  await writeCryptoParam(db, iterKey, iterations);
  return { salt, iterations };
}

async function initEncryption(password: string, username: string): Promise<void> {
  const { salt, iterations } = await getOrCreateCryptoParams(username);
  encryptionKey = await deriveStorageKey(password, salt, iterations);
}

function clearEncryptionKey(): void {
  encryptionKey = null;
}

function uint8ToBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]!);
  }
  return btoa(binary);
}

async function encryptValue(value: unknown): Promise<EncryptedValue> {
  if (!encryptionKey) throw new Error('Encryption key not initialized');
  const plaintext = new TextEncoder().encode(JSON.stringify(value));
  // M2: Validate IV is not degenerate (CSPRNG failure detection)
  const iv = crypto.getRandomValues(new Uint8Array(12));
  if (iv.every(byte => byte === 0)) {
    throw new Error('CSPRNG failure: generated all-zero IV');
  }
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    encryptionKey,
    plaintext
  );
  return {
    __encrypted: true,
    iv: uint8ToBase64(iv),
    data: uint8ToBase64(new Uint8Array(ciphertext)),
  };
}

async function decryptValue(stored: unknown): Promise<unknown> {
  if (!stored) return stored;
  const enc = stored as Partial<EncryptedValue>;
  if (enc.__encrypted && !encryptionKey) throw new Error('Encryption key not initialized');
  if (!enc.__encrypted) return stored;
  const iv = Uint8Array.from(atob(enc.iv!), c => c.charCodeAt(0));
  const data = Uint8Array.from(atob(enc.data!), c => c.charCodeAt(0));
  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    encryptionKey!,
    data
  );
  return JSON.parse(new TextDecoder().decode(plaintext));
}

function open(): Promise<IDBDatabase> {
  if (dbInstance) return Promise.resolve(dbInstance);

  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);

    request.onupgradeneeded = (e) => {
      const db = (e.target as IDBOpenDBRequest).result;
      for (const name of Object.values(STORES)) {
        if (!db.objectStoreNames.contains(name)) {
          db.createObjectStore(name);
        }
      }
    };

    request.onblocked = () => {
      reject(new Error('Database upgrade blocked'));
    };

    request.onsuccess = (e) => {
      dbInstance = (e.target as IDBOpenDBRequest).result;
      resolve(dbInstance);
    };

    request.onerror = () => reject(request.error);
  });
}

async function get(storeName: string, key: string): Promise<unknown> {
  const db = await open();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, 'readonly');
    const req = tx.objectStore(storeName).get(key);
    req.onsuccess = async () => {
      try {
        if (ENCRYPTED_STORES.has(storeName)) {
          resolve(await decryptValue(req.result));
        } else {
          resolve(req.result);
        }
      } catch {
        resolve(undefined);
      }
    };
    req.onerror = () => reject(req.error);
  });
}

async function put(storeName: string, key: string, value: unknown): Promise<void> {
  const db = await open();
  let stored: unknown = value;
  if (ENCRYPTED_STORES.has(storeName)) {
    stored = await encryptValue(value);
  }
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, 'readwrite');
    const req = tx.objectStore(storeName).put(stored, key);
    req.onsuccess = () => resolve();
    req.onerror = () => reject(req.error);
  });
}

// Debounced put - coalesces rapid writes to the same key
function putDebounced(storeName: string, key: string, value: unknown): void {
  const batchKey = `${storeName}:${key}`;
  pendingWrites.set(batchKey, { storeName, key, value });
  if (!flushTimer) {
    flushTimer = setTimeout(flushPendingWrites, FLUSH_DELAY_MS);
  }
}

async function flushPendingWrites(): Promise<void> {
  flushTimer = null;
  if (pendingWrites.size === 0) return;

  // Group by store for batch transactions
  const byStore = new Map<string, PendingWrite[]>();
  for (const [, entry] of pendingWrites) {
    if (!byStore.has(entry.storeName)) byStore.set(entry.storeName, []);
    byStore.get(entry.storeName)!.push(entry);
  }
  pendingWrites.clear();

  const db = await open();

  for (const [storeName, entries] of byStore) {
    // Encrypt all values first
    const prepared: { key: string; stored: unknown }[] = [];
    for (const entry of entries) {
      let stored: unknown = entry.value;
      if (ENCRYPTED_STORES.has(storeName)) {
        stored = await encryptValue(entry.value);
      }
      prepared.push({ key: entry.key, stored });
    }

    // Write all in a single transaction
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction(storeName, 'readwrite');
      const store = tx.objectStore(storeName);
      for (const { key, stored } of prepared) {
        store.put(stored, key);
      }
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  }
}

async function remove(storeName: string, key: string): Promise<void> {
  const db = await open();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, 'readwrite');
    const req = tx.objectStore(storeName).delete(key);
    req.onsuccess = () => resolve();
    req.onerror = () => reject(req.error);
  });
}

async function getAll(storeName: string): Promise<{ keys: IDBValidKey[]; values: unknown[] }> {
  const db = await open();
  const rawEntries = await new Promise<{ key: IDBValidKey; value: unknown }[]>((resolve, reject) => {
    const tx = db.transaction(storeName, 'readonly');
    const store = tx.objectStore(storeName);
    const entries: { key: IDBValidKey; value: unknown }[] = [];
    const cursorReq = store.openCursor();
    cursorReq.onsuccess = (e) => {
      const cursor = (e.target as IDBRequest<IDBCursorWithValue | null>).result;
      if (cursor) {
        entries.push({ key: cursor.key, value: cursor.value });
        cursor.continue();
      } else {
        resolve(entries);
      }
    };
    cursorReq.onerror = () => reject(cursorReq.error);
  });

  // Decrypt outside the transaction
  const keys: IDBValidKey[] = [];
  const values: unknown[] = [];
  for (const entry of rawEntries) {
    keys.push(entry.key);
    try {
      if (ENCRYPTED_STORES.has(storeName)) {
        values.push(await decryptValue(entry.value));
      } else {
        values.push(entry.value);
      }
    } catch {
      values.push(undefined);
    }
  }
  return { keys, values };
}

async function clear(storeName: string): Promise<void> {
  const db = await open();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, 'readwrite');
    const req = tx.objectStore(storeName).clear();
    req.onsuccess = () => resolve();
    req.onerror = () => reject(req.error);
  });
}

async function clearAll(): Promise<void> {
  const db = await open();
  const storeNames = Object.values(STORES);
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeNames as string[], 'readwrite');
    for (const name of storeNames) {
      tx.objectStore(name).clear();
    }
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

// C1: Re-encrypt all stores with a new password (called after password change)
// Two-phase approach: Phase 1 reads/re-encrypts in memory, Phase 2 writes to IndexedDB.
// On Phase 1 failure: no changes made to IndexedDB.
// On Phase 2 failure: old encryption key is restored so unmodified stores remain readable.
// Phase 2 uses a single atomic multi-store IndexedDB transaction for all writes.
async function reEncryptAllStores(oldPassword: string, newPassword: string, username: string): Promise<void> {
  if (reencryptionInProgress) {
    throw new Error('Re-encryption already in progress');
  }
  reencryptionInProgress = true;

  // Flush any pending debounced writes before we snapshot the encryption key,
  // so they commit with the current key and are included in our Phase 1 read.
  await flushPendingWrites();

  const savedEncryptionKey = encryptionKey;

  try {
    // --- Phase 1 (Read-only): Decrypt all data, re-encrypt in memory ---
    // No IndexedDB writes happen in this phase. If anything fails, the DB is unchanged.

    // 1a. Derive old key and decrypt all stores
    const { salt: oldSalt, iterations: oldIter } = await getOrCreateCryptoParams(username);
    const oldKey = await deriveStorageKey(oldPassword, oldSalt, oldIter);
    encryptionKey = oldKey;

    const decryptedData = new Map<string, { keys: IDBValidKey[]; values: unknown[] }>();
    for (const storeName of ENCRYPTED_STORES) {
      const data = await getAll(storeName);
      decryptedData.set(storeName, data);
    }

    // 1b. Generate new salt, derive new key, and re-encrypt all data in memory
    const newSalt = crypto.getRandomValues(new Uint8Array(32));
    const newIter = PBKDF2_ITERATIONS;
    const saltKey = `salt:${username}`;
    const iterKey = `iterations:${username}`;
    const newKey = await deriveStorageKey(newPassword, newSalt, newIter);
    encryptionKey = newKey;

    const reEncryptedData = new Map<string, { keys: IDBValidKey[]; encryptedValues: EncryptedValue[] }>();
    for (const [storeName, data] of decryptedData) {
      const encryptedValues: EncryptedValue[] = [];
      for (let i = 0; i < data.values.length; i++) {
        encryptedValues.push(await encryptValue(data.values[i]));
      }
      reEncryptedData.set(storeName, { keys: data.keys, encryptedValues });
    }

    // --- Phase 2 (Write): Atomically clear and rewrite all stores ---
    // Uses a single multi-store IndexedDB transaction so all writes succeed or
    // all are rolled back by the browser. If this fails, we restore the old
    // encryption key so existing (unchanged) data remains readable.

    const db = await open();
    const storeNames = [...Array.from(reEncryptedData.keys()), STORES.CRYPTO_PARAMS];
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction(storeNames, 'readwrite');
      for (const [storeName, data] of reEncryptedData) {
        const store = tx.objectStore(storeName);
        store.clear();
        for (let i = 0; i < data.keys.length; i++) {
          store.put(data.encryptedValues[i], data.keys[i]);
        }
      }
      // Also update salt and iteration count atomically
      const cryptoStore = tx.objectStore(STORES.CRYPTO_PARAMS);
      cryptoStore.put(uint8ToBase64(newSalt), saltKey);
      cryptoStore.put(newIter, iterKey);
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });

    // Success: encryptionKey is now set to the new key
  } catch (error) {
    // Restore old encryption key so existing data remains readable.
    // On Phase 1 failure the DB is unchanged; on Phase 2 failure the atomic
    // transaction was rolled back by IndexedDB, so the DB is also unchanged.
    encryptionKey = savedEncryptionKey;
    throw error;
  } finally {
    reencryptionInProgress = false;
  }
}

// M5: Upgrade PBKDF2 iteration count for existing users
async function upgradeIterationsIfNeeded(password: string, username: string): Promise<void> {
  const db = await open();
  const iterKey = `iterations:${username}`;
  const existingIter = await readCryptoParam(db, iterKey) as number | undefined;
  if (existingIter && existingIter < PBKDF2_ITERATIONS) {
    await reEncryptAllStores(password, password, username);
  }
}

export { STORES, open, get, put, putDebounced, remove, getAll, clear, clearAll, initEncryption, clearEncryptionKey, reEncryptAllStores, upgradeIterationsIfNeeded };
export type { StoreName };
