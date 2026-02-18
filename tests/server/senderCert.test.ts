import { describe, it, expect, vi, beforeAll } from 'vitest';
import crypto from 'crypto';

// Mock config and logger before importing senderCert
vi.mock('../../server/config', () => ({
  default: { IS_PRODUCTION: false },
}));
vi.mock('../../server/logger', () => ({
  default: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

import {
  issueSenderCertificate,
  verifySenderCertificate,
  getServerPublicKey,
  getSigningKey,
} from '../../server/senderCert';

describe('senderCert', () => {
  describe('issueSenderCertificate', () => {
    it('returns a certificate with payload and signature', () => {
      const cert = issueSenderCertificate(1, 'alice', 'identityKeyBase64');
      expect(cert).toHaveProperty('payload');
      expect(cert).toHaveProperty('signature');
      expect(typeof cert.payload).toBe('string');
      expect(typeof cert.signature).toBe('string');
    });

    it('payload contains correct user data', () => {
      const cert = issueSenderCertificate(42, 'bob', 'bobKeyB64');
      const payload = JSON.parse(Buffer.from(cert.payload, 'base64').toString());
      expect(payload.userId).toBe(42);
      expect(payload.username).toBe('bob');
      expect(payload.identityKey).toBe('bobKeyB64');
      expect(payload.expires).toBeGreaterThan(Math.floor(Date.now() / 1000));
    });

    it('sets expiry to ~24h in the future', () => {
      const now = Math.floor(Date.now() / 1000);
      const cert = issueSenderCertificate(1, 'alice', 'key');
      const payload = JSON.parse(Buffer.from(cert.payload, 'base64').toString());
      const diff = payload.expires - now;
      // Should be within a few seconds of 86400
      expect(diff).toBeGreaterThan(86390);
      expect(diff).toBeLessThanOrEqual(86400);
    });
  });

  describe('verifySenderCertificate', () => {
    it('verifies a freshly issued certificate', () => {
      const cert = issueSenderCertificate(1, 'alice', 'aliceKey');
      const result = verifySenderCertificate(cert);
      expect(result).not.toBeNull();
      expect(result!.userId).toBe(1);
      expect(result!.username).toBe('alice');
      expect(result!.identityKey).toBe('aliceKey');
    });

    it('rejects a certificate with tampered payload', () => {
      const cert = issueSenderCertificate(1, 'alice', 'key');
      // Tamper with the payload
      const payload = JSON.parse(Buffer.from(cert.payload, 'base64').toString());
      payload.username = 'mallory';
      const tampered = {
        payload: Buffer.from(JSON.stringify(payload)).toString('base64'),
        signature: cert.signature,
      };
      expect(verifySenderCertificate(tampered)).toBeNull();
    });

    it('rejects a certificate with tampered signature', () => {
      const cert = issueSenderCertificate(1, 'alice', 'key');
      // Corrupt the signature
      const sigBytes = Buffer.from(cert.signature, 'base64');
      sigBytes[0] ^= 0xff;
      const tampered = {
        payload: cert.payload,
        signature: sigBytes.toString('base64'),
      };
      expect(verifySenderCertificate(tampered)).toBeNull();
    });

    it('rejects an expired certificate', () => {
      // Issue a cert, then manually set expiry well past the 5-minute tolerance
      const payload = {
        userId: 1,
        username: 'alice',
        identityKey: 'key',
        expires: Math.floor(Date.now() / 1000) - 600, // expired 10 minutes ago
      };
      const payloadBytes = Buffer.from(JSON.stringify(payload));
      const payloadB64 = payloadBytes.toString('base64');
      const key = getSigningKey();
      const sig = crypto.sign(null, payloadBytes, key);
      const cert = { payload: payloadB64, signature: sig.toString('base64') };

      // Signature is valid but expiry is past
      expect(verifySenderCertificate(cert)).toBeNull();
    });

    it('rejects completely invalid data', () => {
      expect(verifySenderCertificate({ payload: 'not-valid', signature: 'not-valid' })).toBeNull();
      expect(verifySenderCertificate({ payload: '', signature: '' })).toBeNull();
    });

    it('rejects a certificate signed by a different key', () => {
      const otherKey = crypto.generateKeyPairSync('ed25519');
      const payload = {
        userId: 1, username: 'alice', identityKey: 'key',
        expires: Math.floor(Date.now() / 1000) + 86400,
      };
      const payloadBytes = Buffer.from(JSON.stringify(payload));
      const sig = crypto.sign(null, payloadBytes, otherKey.privateKey);
      const cert = {
        payload: payloadBytes.toString('base64'),
        signature: sig.toString('base64'),
      };
      expect(verifySenderCertificate(cert)).toBeNull();
    });
  });

  describe('getServerPublicKey', () => {
    it('returns a base64-encoded SPKI public key', () => {
      const pubKey = getServerPublicKey();
      expect(typeof pubKey).toBe('string');
      // Should be valid base64 that can be imported
      const der = Buffer.from(pubKey, 'base64');
      expect(der.length).toBeGreaterThan(0);
      // Verify it's a valid SPKI key
      const key = crypto.createPublicKey({ key: der, format: 'der', type: 'spki' });
      expect(key.type).toBe('public');
    });
  });

  describe('getSigningKey', () => {
    it('returns an Ed25519 private key', () => {
      const key = getSigningKey();
      expect(key.type).toBe('private');
      expect(key.asymmetricKeyType).toBe('ed25519');
    });
  });
});
