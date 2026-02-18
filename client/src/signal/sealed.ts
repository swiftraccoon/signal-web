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

// PKCS8 DER prefix for X25519 private keys (RFC 8410).
// The W3C Web Crypto spec only defines 'raw' format for X25519 PUBLIC keys;
// private keys must use 'pkcs8'. Some runtimes (Node.js, Chrome) accept raw
// private keys as an extension, but Firefox follows the spec strictly.
const X25519_PKCS8_PREFIX = new Uint8Array([
  0x30, 0x2e,             // SEQUENCE (46 bytes)
  0x02, 0x01, 0x00,       //   INTEGER 0 (version)
  0x30, 0x05,             //   SEQUENCE (5 bytes)
  0x06, 0x03, 0x2b, 0x65, 0x6e, // OID 1.3.101.110 (X25519)
  0x04, 0x22,             //   OCTET STRING (34 bytes)
  0x04, 0x20,             //     OCTET STRING (32 bytes) — the raw key
]);

// Import raw X25519 private key (32 bytes) as a CryptoKey via PKCS8 wrapping
async function importX25519Private(rawKey: ArrayBuffer): Promise<CryptoKey> {
  const pkcs8 = new Uint8Array(X25519_PKCS8_PREFIX.length + 32);
  pkcs8.set(X25519_PKCS8_PREFIX);
  pkcs8.set(new Uint8Array(rawKey), X25519_PKCS8_PREFIX.length);
  try {
    return await crypto.subtle.importKey(
      'pkcs8', pkcs8.buffer, { name: 'X25519' }, false, ['deriveBits'],
    );
  } finally {
    // Zero the PKCS8 buffer (contains raw private key bytes)
    pkcs8.fill(0);
  }
}

// Generate ephemeral X25519 key pair
async function generateEphemeralKeyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey({ name: 'X25519' }, false, ['deriveBits']) as Promise<CryptoKeyPair>;
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
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32) as BufferSource, info: info as BufferSource },
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
  gossipHash?: string; // sender's own key log hash for split-view detection
}

const SEALED_SENDER_VERSION = 1;
const HKDF_INFO = new TextEncoder().encode('signal-web-sealed-sender-v1');
const CLOCK_SKEW_TOLERANCE_SECONDS = 300; // IMP-5: 5-minute tolerance for clock drift

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
  gossipHash?: string,
): Promise<SealedEnvelope> {
  // The recipient's identity key is a Signal key (Curve25519), stored as base64.
  // Signal keys have a 0x05 prefix byte for the public key format.
  const rawIdentityKey = b642ab(recipientIdentityKey);
  let identityKeyBytes = new Uint8Array(rawIdentityKey);

  // Strip the 0x05 Signal prefix if present (X25519 raw keys are 32 bytes)
  if (identityKeyBytes.length === 33 && identityKeyBytes[0] === 0x05) {
    identityKeyBytes = identityKeyBytes.slice(1);
  }

  const recipientKey = await importX25519Public(identityKeyBytes.buffer);

  // Generate ephemeral X25519 key pair
  const ephemeral = await generateEphemeralKeyPair();

  // Derive AES-256-GCM key from ECDH(ephemeral, recipient) + HKDF
  const aesKey = await deriveSymmetricKey(ephemeral.privateKey, recipientKey, HKDF_INFO);

  // Build inner payload
  const payload: SealedPayload = {
    senderCert,
    message: encryptedMessage,
  };
  if (gossipHash) {
    payload.gossipHash = gossipHash;
  }
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
  zeroArrayBuffer(payloadBytes.buffer);

  return {
    version: SEALED_SENDER_VERSION,
    ephemeralKey: ab2b64(ephemeralPub),
    iv: ab2b64(iv.buffer),
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

  // CRIT-5 fix: validate private key length before import
  if (identityPrivateKey.byteLength !== 32) {
    throw new Error('Identity private key must be exactly 32 bytes');
  }

  // Import recipient's private key for X25519 (PKCS8 format required by spec)
  const privKey = await importX25519Private(identityPrivateKey);

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

/**
 * CRIT-2: Verify a key log entry's Ed25519 signature and hash integrity.
 * Prevents a malicious server from fabricating key log entries.
 */
export async function verifyKeyLogEntry(entry: {
  sequence: number; userId: number; identityKey: string;
  previousHash: string; entryHash: string; signature: string;
}): Promise<boolean> {
  if (!cachedServerKey) return false;

  try {
    // Recompute hash from entry fields (must match server's computeEntryHash format)
    const preimage = `${entry.sequence}:${entry.userId}:${entry.identityKey}:${entry.previousHash}`;
    const hashBuffer = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(preimage));
    const hashHex = Array.from(new Uint8Array(hashBuffer))
      .map(b => b.toString(16).padStart(2, '0')).join('');

    // Verify computed hash matches claimed hash
    if (hashHex !== entry.entryHash) return false;

    // Verify Ed25519 signature over the entry hash string
    const signatureBytes = Uint8Array.from(atob(entry.signature), c => c.charCodeAt(0));
    const hashBytes = new TextEncoder().encode(entry.entryHash);

    return await crypto.subtle.verify({ name: 'Ed25519' }, cachedServerKey, signatureBytes, hashBytes);
  } catch {
    return false;
  }
}

export async function verifySenderCertificate(cert: SenderCertificate): Promise<{
  userId: number; username: string; identityKey: string; expires: number;
} | null> {
  if (!cachedServerKey) return null;

  try {
    const payloadBytes = Uint8Array.from(atob(cert.payload), c => c.charCodeAt(0));
    const signatureBytes = Uint8Array.from(atob(cert.signature), c => c.charCodeAt(0));

    const valid = await crypto.subtle.verify(
      { name: 'Ed25519' }, cachedServerKey, signatureBytes, payloadBytes,
    );
    if (!valid) return null;

    const payload = JSON.parse(new TextDecoder().decode(payloadBytes)) as {
      userId: number; username: string; identityKey: string; expires: number;
    };

    // Check expiry (IMP-5: with clock skew tolerance)
    if (payload.expires + CLOCK_SKEW_TOLERANCE_SECONDS < Math.floor(Date.now() / 1000)) return null;

    return payload;
  } catch (err) {
    console.error('Sender certificate verification failed:', err);
    return null;
  }
}
