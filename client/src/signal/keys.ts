import { KeyHelper } from '@privacyresearch/libsignal-protocol-typescript';
import { ab2b64 } from './store';
import { STORES, get, put } from '../storage/indexeddb';
import type { PreKeyBundleUpload, PreKeyPublic, SignedPreKeyPublic } from '../../../shared/types';
import type { SignalProtocolStore } from './store';

const PREKEY_BATCH_SIZE = 100;
const SIGNED_PREKEY_ROTATION_MS = 7 * 24 * 60 * 60 * 1000; // 7 days

export async function generateAndStoreKeys(store: SignalProtocolStore): Promise<PreKeyBundleUpload> {
  const identityKeyPair = await KeyHelper.generateIdentityKeyPair();
  const registrationId = KeyHelper.generateRegistrationId();

  // Sign pre-key BEFORE saving identity key pair — saveIdentityKeyPair
  // zeros identityKeyPair.privKey in place (H7 hardening), so we must
  // use the private key for signing first.
  const signedPreKeyId = 1;
  const signedPreKey = await KeyHelper.generateSignedPreKey(identityKeyPair, signedPreKeyId);

  // Generate one-time pre-keys
  const preKeys: PreKeyPublic[] = [];
  for (let i = 1; i <= PREKEY_BATCH_SIZE; i++) {
    const preKey = await KeyHelper.generatePreKey(i);
    preKeys.push({
      keyId: preKey.keyId,
      publicKey: ab2b64(preKey.keyPair.pubKey),
    });
    await store.storePreKey(preKey.keyId, preKey.keyPair);
  }

  // Build the upload bundle before saving identity key pair (which zeros privKey)
  const bundle: PreKeyBundleUpload = {
    registrationId,
    identityKey: ab2b64(identityKeyPair.pubKey),
    signedPreKey: {
      keyId: signedPreKey.keyId,
      publicKey: ab2b64(signedPreKey.keyPair.pubKey),
      signature: ab2b64(signedPreKey.signature),
    },
    preKeys,
  };

  // Now safe to save (zeros privKey) and store remaining data
  await store.saveIdentityKeyPair(identityKeyPair);
  await store.saveLocalRegistrationId(registrationId);
  await store.storeSignedPreKey(signedPreKey.keyId, signedPreKey.keyPair);
  await put(STORES.META, 'signedPreKeyId', signedPreKeyId);
  await put(STORES.META, 'signedPreKeyTimestamp', Date.now());
  await put(STORES.META, 'nextPreKeyId', PREKEY_BATCH_SIZE + 1);

  return bundle;
}

// L11: Wrap pre-key IDs to prevent overflow beyond Number.MAX_SAFE_INTEGER
const MAX_PREKEY_ID = 0xFFFFFF; // 16M — safe upper bound for key IDs

export async function generateMorePreKeys(store: SignalProtocolStore, count = PREKEY_BATCH_SIZE): Promise<PreKeyPublic[]> {
  let nextId = (await get(STORES.META, 'nextPreKeyId') as number | undefined) || PREKEY_BATCH_SIZE + 1;

  // L11: Wrap around if approaching unsafe range
  if (nextId > MAX_PREKEY_ID) {
    nextId = 1;
  }

  const preKeys: PreKeyPublic[] = [];
  for (let i = 0; i < count; i++) {
    const keyId = ((nextId + i - 1) % MAX_PREKEY_ID) + 1; // 1-based wrap
    const preKey = await KeyHelper.generatePreKey(keyId);
    await store.storePreKey(preKey.keyId, preKey.keyPair);
    preKeys.push({
      keyId: preKey.keyId,
      publicKey: ab2b64(preKey.keyPair.pubKey),
    });
  }

  const lastId = ((nextId + count - 1) % MAX_PREKEY_ID) + 1;
  await put(STORES.META, 'nextPreKeyId', lastId);
  return preKeys;
}

// Rotate signed pre-key if older than SIGNED_PREKEY_ROTATION_MS
// Returns new bundle data to upload, or null if no rotation needed
export async function rotateSignedPreKeyIfNeeded(store: SignalProtocolStore): Promise<SignedPreKeyPublic | null> {
  const timestamp = await get(STORES.META, 'signedPreKeyTimestamp') as number | undefined;
  if (timestamp && (Date.now() - timestamp) < SIGNED_PREKEY_ROTATION_MS) {
    return null; // No rotation needed
  }

  const identityKeyPair = await store.getIdentityKeyPair();
  if (!identityKeyPair) return null;

  const oldKeyId = (await get(STORES.META, 'signedPreKeyId') as number | undefined) || 1;
  const newKeyId = oldKeyId + 1;

  const signedPreKey = await KeyHelper.generateSignedPreKey(identityKeyPair, newKeyId);
  await store.storeSignedPreKey(signedPreKey.keyId, signedPreKey.keyPair);

  // L6: Update metadata BEFORE deleting old keys — if we crash mid-operation,
  // the worst case is an orphaned key in the store (harmless) rather than a
  // referenced key that no longer exists.
  await put(STORES.META, 'signedPreKeyId', newKeyId);
  await put(STORES.META, 'signedPreKeyTimestamp', Date.now());

  // Keep old signed pre-key for grace period (48h) to allow in-flight sessions to complete
  // Schedule removal of the previous old key (two rotations ago)
  const prevOldKeyId = await get(STORES.META, 'prevSignedPreKeyId') as number | undefined;
  await put(STORES.META, 'prevSignedPreKeyId', oldKeyId);
  if (prevOldKeyId) {
    await store.removeSignedPreKey(prevOldKeyId);
  }

  // Remove the two lines that were previously here — they're now above
  return {
    keyId: signedPreKey.keyId,
    publicKey: ab2b64(signedPreKey.keyPair.pubKey),
    signature: ab2b64(signedPreKey.signature),
  };
}
