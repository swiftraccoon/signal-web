import crypto from 'crypto';
import config from './config';
import logger from './logger';

// Ed25519 key pair for signing sender certificates.
// In production: loaded from SENDER_CERT_PRIVATE_KEY env var (base64 DER).
// In dev: auto-generated on startup (certs won't survive restarts).

let signingKey: crypto.KeyObject;
let publicKey: crypto.KeyObject;

function initSenderCertKeys(): void {
  const privKeyEnv = process.env.SENDER_CERT_PRIVATE_KEY;

  if (privKeyEnv) {
    const der = Buffer.from(privKeyEnv, 'base64');
    signingKey = crypto.createPrivateKey({ key: der, format: 'der', type: 'pkcs8' });
    publicKey = crypto.createPublicKey(signingKey);
    logger.info('Sender certificate signing key loaded from environment');
  } else {
    if (config.IS_PRODUCTION) {
      logger.error('FATAL: SENDER_CERT_PRIVATE_KEY must be set in production');
      process.exit(1);
    }
    const pair = crypto.generateKeyPairSync('ed25519');
    signingKey = pair.privateKey;
    publicKey = pair.publicKey;
    logger.warn('WARNING: Using ephemeral sender cert key (dev only)');
  }
}

// Initialize on module load
initSenderCertKeys();

export interface SenderCertificate {
  payload: string; // base64-encoded JSON
  signature: string; // base64-encoded Ed25519 signature
}

interface SenderCertPayload {
  userId: number;
  username: string;
  identityKey: string;
  expires: number; // unix epoch seconds
}

const CERT_EXPIRY_SECONDS = 24 * 60 * 60; // 24 hours

export function issueSenderCertificate(userId: number, username: string, identityKey: string): SenderCertificate {
  const payload: SenderCertPayload = {
    userId,
    username,
    identityKey,
    expires: Math.floor(Date.now() / 1000) + CERT_EXPIRY_SECONDS,
  };

  const payloadBytes = Buffer.from(JSON.stringify(payload));
  const payloadB64 = payloadBytes.toString('base64');

  const signature = crypto.sign(null, payloadBytes, signingKey);

  return {
    payload: payloadB64,
    signature: signature.toString('base64'),
  };
}

export function verifySenderCertificate(cert: SenderCertificate): SenderCertPayload | null {
  try {
    const payloadBytes = Buffer.from(cert.payload, 'base64');
    const signatureBytes = Buffer.from(cert.signature, 'base64');

    const valid = crypto.verify(null, payloadBytes, publicKey, signatureBytes);
    if (!valid) return null;

    const payload = JSON.parse(payloadBytes.toString()) as SenderCertPayload;

    // Check expiry
    if (payload.expires < Math.floor(Date.now() / 1000)) return null;

    return payload;
  } catch {
    return null;
  }
}

export function getServerPublicKey(): string {
  return publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
}

export function getSigningKey(): crypto.KeyObject {
  return signingKey;
}
