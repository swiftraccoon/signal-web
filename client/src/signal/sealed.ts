// Sealed Sender: two-layer envelope encryption that hides the sender's identity from the server.
//
// Outer layer: ephemeral X25519 ECDH + HKDF-SHA256 → AES-256-GCM
//   - Encrypted to recipient's identity public key
//   - Server cannot read this; only the recipient can unwrap
//
// Inner payload: { senderCert, encryptedMessage (Signal ciphertext) }
//   - senderCert proves who sent it (Ed25519-signed by server)
//   - encryptedMessage is the normal Signal Protocol ciphertext

import { ab2b64, b642ab, zeroArrayBuffer } from './store';
import type { SenderCertificate } from '../../../shared/types';

// Convert raw X25519 public key (32 bytes) to CryptoKey for ECDH
async function importX25519Public(raw: ArrayBuffer): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', raw, { name: 'X25519' }, false, []);
}

// Generate ephemeral X25519 key pair
async function generateEphemeralKeyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey({ name: 'X25519' }, false, ['deriveBits']);
}

// Derive shared secret via ECDH, then expand with HKDF-SHA256
async function deriveSymmetricKey(
  privateKey: CryptoKey,
  publicKey: CryptoKey,
  info: Uint8Array,
): Promise<CryptoKey> {
  // ECDH: derive 32 bytes of shared secret
  const sharedBits = await crypto.subtle.deriveBits(
    { name: 'X25519', public: publicKey },
    privateKey,
    256,
  );

  // Import shared secret as HKDF key material
  const hkdfKey = await crypto.subtle.importKey(
    'raw', sharedBits, 'HKDF', false, ['deriveKey'],
  );

  // HKDF-SHA256: expand into AES-256-GCM key
  // Salt is empty (ephemeral ECDH already provides randomness via the ephemeral key)
  const aesKey = await crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info },
    hkdfKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );

  // Zero the raw shared secret
  zeroArrayBuffer(sharedBits);

  return aesKey;
}

export interface SealedEnvelope {
  version: number;
  ephemeralKey: string;   // base64-encoded raw X25519 public key (32 bytes)
  iv: string;             // base64-encoded 12-byte IV
  ciphertext: string;     // base64-encoded AES-GCM ciphertext
}

interface SealedPayload {
  senderCert: SenderCertificate;
  message: { type: number; body: string };
}

const SEALED_SENDER_VERSION = 1;
const HKDF_INFO = new TextEncoder().encode('signal-web-sealed-sender-v1');

/**
 * Seal an encrypted message so the server cannot see who sent it.
 *
 * @param recipientIdentityKey - Recipient's Signal identity public key (base64)
 * @param senderCert - Sender's server-signed certificate
 * @param encryptedMessage - Signal Protocol ciphertext { type, body }
 * @returns SealedEnvelope ready for transmission
 */
export async function sealMessage(
  recipientIdentityKey: string,
  senderCert: SenderCertificate,
  encryptedMessage: { type: number; body: string },
): Promise<SealedEnvelope> {
  // The recipient's identity key is a Signal key (Curve25519), stored as base64.
  // Signal keys have a 0x05 prefix byte for the public key format.
  const rawIdentityKey = b642ab(recipientIdentityKey);
  let identityKeyBytes = new Uint8Array(rawIdentityKey);

  // Strip the 0x05 Signal prefix if present (X25519 raw keys are 32 bytes)
  if (identityKeyBytes.length === 33 && identityKeyBytes[0] === 0x05) {
    identityKeyBytes = identityKeyBytes.slice(1);
  }

  const recipientKey = await importX25519Public(identityKeyBytes.buffer as ArrayBuffer);

  // Generate ephemeral X25519 key pair
  const ephemeral = await generateEphemeralKeyPair();

  // Derive AES-256-GCM key from ECDH(ephemeral, recipient) + HKDF
  const aesKey = await deriveSymmetricKey(ephemeral.privateKey, recipientKey, HKDF_INFO);

  // Build inner payload
  const payload: SealedPayload = {
    senderCert,
    message: encryptedMessage,
  };
  const payloadBytes = new TextEncoder().encode(JSON.stringify(payload));

  // Encrypt with AES-256-GCM
  const iv = crypto.getRandomValues(new Uint8Array(12));
  if (iv.every(b => b === 0)) throw new Error('CSPRNG failure: all-zero IV');

  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    aesKey,
    payloadBytes,
  );

  // Export ephemeral public key as raw bytes
  const ephemeralPub = await crypto.subtle.exportKey('raw', ephemeral.publicKey);

  // Zero sensitive buffers
  zeroArrayBuffer(payloadBytes.buffer as ArrayBuffer);

  return {
    version: SEALED_SENDER_VERSION,
    ephemeralKey: ab2b64(ephemeralPub),
    iv: ab2b64(iv.buffer as ArrayBuffer),
    ciphertext: ab2b64(ciphertext),
  };
}

/**
 * Unseal a sealed sender message using the recipient's identity private key.
 *
 * @param envelope - The sealed envelope from the server
 * @param identityPrivateKey - Recipient's Signal identity private key (ArrayBuffer, 32 bytes)
 * @returns The decrypted payload containing sender certificate and encrypted message
 */
export async function unsealMessage(
  envelope: SealedEnvelope,
  identityPrivateKey: ArrayBuffer,
): Promise<SealedPayload> {
  if (envelope.version !== SEALED_SENDER_VERSION) {
    throw new Error(`Unknown sealed sender version: ${envelope.version}`);
  }

  // Import recipient's private key for X25519
  const privKey = await crypto.subtle.importKey(
    'raw', identityPrivateKey, { name: 'X25519' }, false, ['deriveBits'],
  );

  // Import sender's ephemeral public key
  const ephemeralPubBytes = b642ab(envelope.ephemeralKey);
  const ephemeralPub = await importX25519Public(ephemeralPubBytes);

  // Derive the same AES-256-GCM key
  const aesKey = await deriveSymmetricKey(privKey, ephemeralPub, HKDF_INFO);

  // Decrypt
  const iv = b642ab(envelope.iv);
  const ciphertext = b642ab(envelope.ciphertext);

  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    aesKey,
    ciphertext,
  );

  const payload = JSON.parse(new TextDecoder().decode(plaintext)) as SealedPayload;

  // Zero decrypted buffer
  zeroArrayBuffer(plaintext);

  return payload;
}

// Server public key cache for certificate verification
let cachedServerKey: CryptoKey | null = null;

export async function setServerPublicKey(spkiBase64: string): Promise<void> {
  const der = b642ab(spkiBase64);
  cachedServerKey = await crypto.subtle.importKey(
    'spki', der, { name: 'Ed25519' }, false, ['verify'],
  );
}

export async function verifySenderCertificate(cert: SenderCertificate): Promise<{
  userId: number; username: string; identityKey: string; expires: number;
} | null> {
  if (!cachedServerKey) return null;

  const payloadBytes = Uint8Array.from(atob(cert.payload), c => c.charCodeAt(0));
  const signatureBytes = Uint8Array.from(atob(cert.signature), c => c.charCodeAt(0));

  const valid = await crypto.subtle.verify(
    { name: 'Ed25519' }, cachedServerKey, signatureBytes, payloadBytes,
  );
  if (!valid) return null;

  const payload = JSON.parse(new TextDecoder().decode(payloadBytes)) as {
    userId: number; username: string; identityKey: string; expires: number;
  };

  // Check expiry
  if (payload.expires < Math.floor(Date.now() / 1000)) return null;

  return payload;
}
