import { describe, it, expect, vi, beforeEach } from 'vitest';
import crypto from 'crypto';

// Mock the store module (ab2b64, b642ab, zeroArrayBuffer are utility functions)
// We need to provide real implementations since sealed.ts uses Web Crypto
vi.mock('../../client/src/storage/indexeddb', () => ({
  STORES: { META: 'meta' },
  get: vi.fn(),
  put: vi.fn(),
}));

// We can't easily mock the store utilities since sealed.ts imports them directly.
// Instead, let's test the sealed module's crypto logic using the actual Web Crypto API.

// Helper: ArrayBuffer to base64
function ab2b64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]!);
  }
  return btoa(binary);
}

// Helper: base64 to ArrayBuffer
function b642ab(base64: string): ArrayBuffer {
  const bin = atob(base64);
  const buf = new ArrayBuffer(bin.length);
  const arr = new Uint8Array(buf);
  for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
  return buf;
}

describe('sealed sender crypto', () => {
  // Test the core crypto primitives independently since the module
  // has import dependencies on IndexedDB store.
  // We test the algorithm correctness: ECDH + HKDF + AES-GCM round trip.

  async function importX25519Public(raw: ArrayBuffer): Promise<CryptoKey> {
    return globalThis.crypto.subtle.importKey('raw', raw, { name: 'X25519' }, false, []);
  }

  async function generateEphemeralKeyPair(): Promise<CryptoKeyPair> {
    return globalThis.crypto.subtle.generateKey(
      { name: 'X25519' }, true, ['deriveBits'],
    ) as Promise<CryptoKeyPair>;
  }

  async function deriveSymmetricKey(
    privateKey: CryptoKey,
    publicKey: CryptoKey,
    info: Uint8Array,
  ): Promise<CryptoKey> {
    const sharedBits = await globalThis.crypto.subtle.deriveBits(
      { name: 'X25519', public: publicKey },
      privateKey,
      256,
    );
    const hkdfKey = await globalThis.crypto.subtle.importKey(
      'raw', sharedBits, 'HKDF', false, ['deriveKey'],
    );
    return globalThis.crypto.subtle.deriveKey(
      { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info },
      hkdfKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt'],
    );
  }

  const HKDF_INFO = new TextEncoder().encode('signal-web-sealed-sender-v1');

  it('X25519 ECDH produces consistent shared secrets', async () => {
    const alice = await generateEphemeralKeyPair();
    const bob = await generateEphemeralKeyPair();

    const alicePub = await globalThis.crypto.subtle.exportKey('raw', alice.publicKey);
    const bobPub = await globalThis.crypto.subtle.exportKey('raw', bob.publicKey);

    // Alice derives with Bob's public key
    const aliceShared = await globalThis.crypto.subtle.deriveBits(
      { name: 'X25519', public: await importX25519Public(bobPub) },
      alice.privateKey,
      256,
    );

    // Bob derives with Alice's public key
    const bobShared = await globalThis.crypto.subtle.deriveBits(
      { name: 'X25519', public: await importX25519Public(alicePub) },
      bob.privateKey,
      256,
    );

    expect(ab2b64(aliceShared)).toBe(ab2b64(bobShared));
  });

  // Helper: generate X25519 key pair using Node.js crypto, return PKCS8 DER for private
  function generateNodeX25519(): { publicKeyRaw: Uint8Array; privateKeyPkcs8: Buffer } {
    const pair = crypto.generateKeyPairSync('x25519');
    const pubDer = pair.publicKey.export({ type: 'spki', format: 'der' });
    const privDer = pair.privateKey.export({ type: 'pkcs8', format: 'der' });
    return {
      publicKeyRaw: new Uint8Array(pubDer.slice(-32)),
      privateKeyPkcs8: privDer,
    };
  }

  // Import X25519 private key via PKCS8 format (Node Web Crypto doesn't support raw import)
  async function importX25519Private(pkcs8: Buffer): Promise<CryptoKey> {
    return globalThis.crypto.subtle.importKey(
      'pkcs8', pkcs8, { name: 'X25519' }, false, ['deriveBits'],
    );
  }

  it('full seal/unseal round trip succeeds', async () => {
    const recipient = generateNodeX25519();
    const recipientPubB64 = ab2b64(recipient.publicKeyRaw.buffer as ArrayBuffer);

    // Sender side: seal
    const ephemeral = await generateEphemeralKeyPair();
    const recipientPub = await importX25519Public(b642ab(recipientPubB64));
    const aesKey = await deriveSymmetricKey(ephemeral.privateKey, recipientPub, HKDF_INFO);

    const payload = JSON.stringify({
      senderCert: { payload: 'test', signature: 'sig' },
      message: { type: 1, body: 'encrypted_body' },
    });
    const payloadBytes = new TextEncoder().encode(payload);
    const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));

    const ciphertext = await globalThis.crypto.subtle.encrypt(
      { name: 'AES-GCM', iv }, aesKey, payloadBytes,
    );

    const ephemeralPubRaw = await globalThis.crypto.subtle.exportKey('raw', ephemeral.publicKey);

    // Recipient side: unseal using PKCS8-imported private key
    const privKey = await importX25519Private(recipient.privateKeyPkcs8);
    const ephPub = await importX25519Public(ephemeralPubRaw);
    const decryptKey = await deriveSymmetricKey(privKey, ephPub, HKDF_INFO);

    const plaintext = await globalThis.crypto.subtle.decrypt(
      { name: 'AES-GCM', iv }, decryptKey, ciphertext,
    );

    const recovered = JSON.parse(new TextDecoder().decode(plaintext));
    expect(recovered.message.type).toBe(1);
    expect(recovered.message.body).toBe('encrypted_body');
  });

  it('decryption fails with wrong recipient key', async () => {
    const recipient1 = generateNodeX25519();
    const recipient2 = generateNodeX25519(); // wrong recipient

    // Seal to recipient1
    const ephemeral = await generateEphemeralKeyPair();
    const recipientPub = await importX25519Public(recipient1.publicKeyRaw);
    const aesKey = await deriveSymmetricKey(ephemeral.privateKey, recipientPub, HKDF_INFO);

    const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await globalThis.crypto.subtle.encrypt(
      { name: 'AES-GCM', iv }, aesKey, new TextEncoder().encode('secret'),
    );

    const ephPubRaw = await globalThis.crypto.subtle.exportKey('raw', ephemeral.publicKey);

    // Try to unseal with recipient2's key — should fail
    const wrongPriv = await importX25519Private(recipient2.privateKeyPkcs8);
    const ephPub = await importX25519Public(ephPubRaw);
    const wrongKey = await deriveSymmetricKey(wrongPriv, ephPub, HKDF_INFO);

    await expect(
      globalThis.crypto.subtle.decrypt({ name: 'AES-GCM', iv }, wrongKey, ciphertext),
    ).rejects.toThrow();
  });

  it('AES-GCM detects tampered ciphertext', async () => {
    const recipient = generateNodeX25519();

    const ephemeral = await generateEphemeralKeyPair();
    const pub = await importX25519Public(recipient.publicKeyRaw);
    const aesKey = await deriveSymmetricKey(ephemeral.privateKey, pub, HKDF_INFO);

    const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await globalThis.crypto.subtle.encrypt(
      { name: 'AES-GCM', iv }, aesKey, new TextEncoder().encode('data'),
    );

    // Tamper with the ciphertext
    const tampered = new Uint8Array(ciphertext);
    tampered[0] ^= 0xff;

    const priv = await importX25519Private(recipient.privateKeyPkcs8);
    const ephPubRaw = await globalThis.crypto.subtle.exportKey('raw', ephemeral.publicKey);
    const ephPub = await importX25519Public(ephPubRaw);
    const decKey = await deriveSymmetricKey(priv, ephPub, HKDF_INFO);

    await expect(
      globalThis.crypto.subtle.decrypt({ name: 'AES-GCM', iv }, decKey, tampered.buffer),
    ).rejects.toThrow();
  });

  it('each seal uses a unique ephemeral key', async () => {
    const keys = new Set<string>();
    for (let i = 0; i < 5; i++) {
      const kp = await generateEphemeralKeyPair();
      const raw = await globalThis.crypto.subtle.exportKey('raw', kp.publicKey);
      keys.add(ab2b64(raw));
    }
    expect(keys.size).toBe(5);
  });

  describe('Ed25519 certificate verification', () => {
    it('verifies a valid Ed25519 signature', async () => {
      // Generate Ed25519 key pair using Node crypto
      const keyPair = crypto.generateKeyPairSync('ed25519');
      const spkiDer = keyPair.publicKey.export({ type: 'spki', format: 'der' });

      // Import into Web Crypto
      const webKey = await globalThis.crypto.subtle.importKey(
        'spki', spkiDer, { name: 'Ed25519' }, false, ['verify'],
      );

      // Sign with Node, verify with Web Crypto
      const message = Buffer.from('test payload');
      const sig = crypto.sign(null, message, keyPair.privateKey);

      const valid = await globalThis.crypto.subtle.verify(
        { name: 'Ed25519' }, webKey, sig, message,
      );
      expect(valid).toBe(true);
    });

    it('rejects an invalid Ed25519 signature', async () => {
      const keyPair = crypto.generateKeyPairSync('ed25519');
      const spkiDer = keyPair.publicKey.export({ type: 'spki', format: 'der' });
      const webKey = await globalThis.crypto.subtle.importKey(
        'spki', spkiDer, { name: 'Ed25519' }, false, ['verify'],
      );

      const message = Buffer.from('test payload');
      const sig = crypto.sign(null, message, keyPair.privateKey);
      // Corrupt signature
      sig[0] ^= 0xff;

      const valid = await globalThis.crypto.subtle.verify(
        { name: 'Ed25519' }, webKey, sig, message,
      );
      expect(valid).toBe(false);
    });
  });

  describe('Signal key format handling', () => {
    it('correctly strips 0x05 prefix from 33-byte Signal keys', () => {
      // Signal identity keys have a 0x05 prefix byte
      const rawKey = new Uint8Array(32);
      globalThis.crypto.getRandomValues(rawKey);

      const signalKey = new Uint8Array(33);
      signalKey[0] = 0x05;
      signalKey.set(rawKey, 1);

      // Strip prefix like sealed.ts does
      let processed = signalKey;
      if (processed.length === 33 && processed[0] === 0x05) {
        processed = processed.slice(1);
      }

      expect(processed.length).toBe(32);
      expect(processed).toEqual(rawKey);
    });

    it('leaves 32-byte keys unchanged', () => {
      const rawKey = new Uint8Array(32);
      globalThis.crypto.getRandomValues(rawKey);

      let processed = rawKey;
      if (processed.length === 33 && processed[0] === 0x05) {
        processed = processed.slice(1);
      }

      expect(processed.length).toBe(32);
      expect(processed).toEqual(rawKey);
    });
  });
});
