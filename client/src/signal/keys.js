import { KeyHelper } from '@privacyresearch/libsignal-protocol-typescript';
import { ab2b64 } from './store.js';
import { STORES, get, put } from '../storage/indexeddb.js';

const PREKEY_BATCH_SIZE = 100;
const SIGNED_PREKEY_ROTATION_MS = 7 * 24 * 60 * 60 * 1000; // 7 days

export async function generateAndStoreKeys(store) {
  const identityKeyPair = await KeyHelper.generateIdentityKeyPair();
  const registrationId = KeyHelper.generateRegistrationId();

  await store.saveIdentityKeyPair(identityKeyPair);
  await store.saveLocalRegistrationId(registrationId);

  // Generate signed pre-key (key ID = 1)
  const signedPreKeyId = 1;
  const signedPreKey = await KeyHelper.generateSignedPreKey(identityKeyPair, signedPreKeyId);
  await store.storeSignedPreKey(signedPreKey.keyId, signedPreKey.keyPair);
  await put(STORES.META, 'signedPreKeyId', signedPreKeyId);
  await put(STORES.META, 'signedPreKeyTimestamp', Date.now());

  // Generate one-time pre-keys
  const preKeys = [];
  for (let i = 1; i <= PREKEY_BATCH_SIZE; i++) {
    const preKey = await KeyHelper.generatePreKey(i);
    await store.storePreKey(preKey.keyId, preKey.keyPair);
    preKeys.push({
      keyId: preKey.keyId,
      publicKey: ab2b64(preKey.keyPair.pubKey),
    });
  }

  await put(STORES.META, 'nextPreKeyId', PREKEY_BATCH_SIZE + 1);

  return {
    registrationId,
    identityKey: ab2b64(identityKeyPair.pubKey),
    signedPreKey: {
      keyId: signedPreKey.keyId,
      publicKey: ab2b64(signedPreKey.keyPair.pubKey),
      signature: ab2b64(signedPreKey.signature),
    },
    preKeys,
  };
}

export async function generateMorePreKeys(store, count = PREKEY_BATCH_SIZE) {
  let nextId = (await get(STORES.META, 'nextPreKeyId')) || PREKEY_BATCH_SIZE + 1;

  const preKeys = [];
  for (let i = 0; i < count; i++) {
    const preKey = await KeyHelper.generatePreKey(nextId + i);
    await store.storePreKey(preKey.keyId, preKey.keyPair);
    preKeys.push({
      keyId: preKey.keyId,
      publicKey: ab2b64(preKey.keyPair.pubKey),
    });
  }

  await put(STORES.META, 'nextPreKeyId', nextId + count);
  return preKeys;
}

// Rotate signed pre-key if older than SIGNED_PREKEY_ROTATION_MS
// Returns new bundle data to upload, or null if no rotation needed
export async function rotateSignedPreKeyIfNeeded(store) {
  const timestamp = await get(STORES.META, 'signedPreKeyTimestamp');
  if (timestamp && (Date.now() - timestamp) < SIGNED_PREKEY_ROTATION_MS) {
    return null; // No rotation needed
  }

  const identityKeyPair = await store.getIdentityKeyPair();
  if (!identityKeyPair) return null;

  const oldKeyId = (await get(STORES.META, 'signedPreKeyId')) || 1;
  const newKeyId = oldKeyId + 1;

  const signedPreKey = await KeyHelper.generateSignedPreKey(identityKeyPair, newKeyId);
  await store.storeSignedPreKey(signedPreKey.keyId, signedPreKey.keyPair);

  // Keep old signed pre-key for grace period (48h) to allow in-flight sessions to complete
  // Schedule removal of the previous old key (two rotations ago)
  const prevOldKeyId = await get(STORES.META, 'prevSignedPreKeyId');
  if (prevOldKeyId) {
    await store.removeSignedPreKey(prevOldKeyId);
  }
  await put(STORES.META, 'prevSignedPreKeyId', oldKeyId);

  await put(STORES.META, 'signedPreKeyId', newKeyId);
  await put(STORES.META, 'signedPreKeyTimestamp', Date.now());

  return {
    keyId: signedPreKey.keyId,
    publicKey: ab2b64(signedPreKey.keyPair.pubKey),
    signature: ab2b64(signedPreKey.signature),
  };
}
