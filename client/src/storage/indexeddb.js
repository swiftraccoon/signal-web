const DB_NAME = 'signal-web';
const DB_VERSION = 2;

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
  CRYPTO_PARAMS: 'cryptoParams', // Unencrypted store for salt etc.
};

// Stores whose values are encrypted at rest with the local DB key
const ENCRYPTED_STORES = new Set([
  STORES.IDENTITY_KEY_PAIR,
  STORES.PRE_KEYS,
  STORES.SIGNED_PRE_KEYS,
  STORES.SESSIONS,
  STORES.IDENTITY_KEYS,
  STORES.CONTACTS,
  STORES.MESSAGES,
  STORES.META,
  STORES.REGISTRATION_ID,
]);

let dbInstance = null;
let encryptionKey = null; // CryptoKey for AES-GCM

// Write batching - coalesce rapid writes to the same store+key
const pendingWrites = new Map(); // "store:key" -> { storeName, key, value }
let flushTimer = null;
const FLUSH_DELAY_MS = 100;

// Derive a storage encryption key from the user's password + random salt
async function deriveStorageKey(password, saltBytes) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: saltBytes, iterations: 100000, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

// Get or create a random salt, stored unencrypted in CRYPTO_PARAMS
async function getOrCreateSalt(username) {
  const db = await open();
  const saltKey = `salt:${username}`;

  // Read from unencrypted store
  const existing = await new Promise((resolve, reject) => {
    const tx = db.transaction(STORES.CRYPTO_PARAMS, 'readonly');
    const req = tx.objectStore(STORES.CRYPTO_PARAMS).get(saltKey);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });

  if (existing) {
    return Uint8Array.from(atob(existing), c => c.charCodeAt(0));
  }

  // Generate new 32-byte random salt
  const salt = crypto.getRandomValues(new Uint8Array(32));
  const b64Salt = uint8ToBase64(salt);

  await new Promise((resolve, reject) => {
    const tx = db.transaction(STORES.CRYPTO_PARAMS, 'readwrite');
    tx.objectStore(STORES.CRYPTO_PARAMS).put(b64Salt, saltKey);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });

  return salt;
}

async function initEncryption(password, username) {
  const salt = await getOrCreateSalt(username);
  encryptionKey = await deriveStorageKey(password, salt);
}

function clearEncryptionKey() {
  encryptionKey = null;
}

function uint8ToBase64(bytes) {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

async function encryptValue(value) {
  if (!encryptionKey) throw new Error('Encryption key not initialized');
  const plaintext = new TextEncoder().encode(JSON.stringify(value));
  const iv = crypto.getRandomValues(new Uint8Array(12));
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

async function decryptValue(stored) {
  if (!stored) return stored;
  if (stored.__encrypted && !encryptionKey) throw new Error('Encryption key not initialized');
  if (!stored.__encrypted) return stored;
  const iv = Uint8Array.from(atob(stored.iv), c => c.charCodeAt(0));
  const data = Uint8Array.from(atob(stored.data), c => c.charCodeAt(0));
  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    encryptionKey,
    data
  );
  return JSON.parse(new TextDecoder().decode(plaintext));
}

function open() {
  if (dbInstance) return Promise.resolve(dbInstance);

  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);

    request.onupgradeneeded = (e) => {
      const db = e.target.result;
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
      dbInstance = e.target.result;
      resolve(dbInstance);
    };

    request.onerror = () => reject(request.error);
  });
}

async function get(storeName, key) {
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

async function put(storeName, key, value) {
  const db = await open();
  let stored = value;
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
function putDebounced(storeName, key, value) {
  const batchKey = `${storeName}:${key}`;
  pendingWrites.set(batchKey, { storeName, key, value });
  if (!flushTimer) {
    flushTimer = setTimeout(flushPendingWrites, FLUSH_DELAY_MS);
  }
}

async function flushPendingWrites() {
  flushTimer = null;
  if (pendingWrites.size === 0) return;

  // Group by store for batch transactions
  const byStore = new Map();
  for (const [, entry] of pendingWrites) {
    if (!byStore.has(entry.storeName)) byStore.set(entry.storeName, []);
    byStore.get(entry.storeName).push(entry);
  }
  pendingWrites.clear();

  const db = await open();

  for (const [storeName, entries] of byStore) {
    // Encrypt all values first
    const prepared = [];
    for (const entry of entries) {
      let stored = entry.value;
      if (ENCRYPTED_STORES.has(storeName)) {
        stored = await encryptValue(entry.value);
      }
      prepared.push({ key: entry.key, stored });
    }

    // Write all in a single transaction
    await new Promise((resolve, reject) => {
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

async function remove(storeName, key) {
  const db = await open();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, 'readwrite');
    const req = tx.objectStore(storeName).delete(key);
    req.onsuccess = () => resolve();
    req.onerror = () => reject(req.error);
  });
}

async function getAll(storeName) {
  const db = await open();
  const rawEntries = await new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, 'readonly');
    const store = tx.objectStore(storeName);
    const entries = [];
    const cursorReq = store.openCursor();
    cursorReq.onsuccess = (e) => {
      const cursor = e.target.result;
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
  const keys = [];
  const values = [];
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

async function clear(storeName) {
  const db = await open();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, 'readwrite');
    const req = tx.objectStore(storeName).clear();
    req.onsuccess = () => resolve();
    req.onerror = () => reject(req.error);
  });
}

async function clearAll() {
  const db = await open();
  const storeNames = Object.values(STORES);
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeNames, 'readwrite');
    for (const name of storeNames) {
      tx.objectStore(name).clear();
    }
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

export { STORES, open, get, put, putDebounced, remove, getAll, clear, clearAll, initEncryption, clearEncryptionKey };
