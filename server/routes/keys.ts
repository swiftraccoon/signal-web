import express, { Request, Response } from 'express';
import { authenticateToken } from '../middleware/auth';
import { senderCertLimiter } from '../middleware/rateLimiter';
import { stmt, getPreKeyBundle, uploadBundle } from '../db';
import { audit } from '../audit';
import { issueSenderCertificate, getServerPublicKey } from '../senderCert';
import { appendToKeyLog, getKeyLogForUser, getKeyLogRange, getLatestKeyLogForUser } from '../keyLog';
import { PREKEY_LOW_THRESHOLD, WS_MSG_TYPE } from '../../shared/constants';
import { getConnection, isOnline } from '../ws/connections';
import logger from '../logger';
import type { DbUser, DbIdentityKey, DbCount, BundleFetchEntry, PreKeyBundleUpload, PreKeyPublic } from '../../shared/types';

const router = express.Router();

const MAX_PREKEYS_PER_UPLOAD = 200;

// Per-target bundle fetch rate limiting (prevents pre-key exhaustion attacks)
const bundleFetchCounts = new Map<string, BundleFetchEntry>();
const BUNDLE_FETCH_LIMIT = 3; // max fetches per target per window
const BUNDLE_FETCH_WINDOW_MS = 60 * 60 * 1000; // 1 hour

// Periodic cleanup of expired rate limit entries
setInterval(() => {
  const now = Date.now();
  /* eslint-disable @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-argument -- Map<string, BundleFetchEntry> iteration; type not resolved by project service */
  for (const [key, val] of bundleFetchCounts) {
    if (now - val.windowStart > BUNDLE_FETCH_WINDOW_MS) {
      bundleFetchCounts.delete(key);
    }
  }
  /* eslint-enable @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-argument */
}, 5 * 60 * 1000);

router.put('/bundle', authenticateToken, (req: Request, res: Response) => {
  try {
    const bundle = req.body as PreKeyBundleUpload;

    // Validate required fields exist and have correct types
    if (typeof bundle.registrationId !== 'number' || bundle.registrationId < 1 || bundle.registrationId > 0x3FFF) {
      res.status(400).json({ error: 'Invalid registrationId' });
      return;
    }
    if (typeof bundle.identityKey !== 'string' || bundle.identityKey.length === 0 || bundle.identityKey.length > 100) {
      res.status(400).json({ error: 'Invalid identityKey' });
      return;
    }
    if (!bundle.signedPreKey || typeof bundle.signedPreKey.keyId !== 'number'
        || typeof bundle.signedPreKey.publicKey !== 'string' || typeof bundle.signedPreKey.signature !== 'string') {
      res.status(400).json({ error: 'Invalid signedPreKey' });
      return;
    }
    if (!Array.isArray(bundle.preKeys)) {
      res.status(400).json({ error: 'preKeys must be an array' });
      return;
    }
    if (bundle.preKeys.length > MAX_PREKEYS_PER_UPLOAD) {
      res.status(400).json({ error: `Maximum ${MAX_PREKEYS_PER_UPLOAD} pre-keys per upload` });
      return;
    }
    // Validate each preKey
    for (const pk of bundle.preKeys) {
      if (typeof pk.keyId !== 'number' || typeof pk.publicKey !== 'string') {
        res.status(400).json({ error: 'Invalid preKey format' });
        return;
      }
    }

    uploadBundle(req.user!.id, bundle);

    // Append identity key to transparency log
    appendToKeyLog(req.user!.id, bundle.identityKey);

    audit('bundle_uploaded', { userId: req.user!.id, username: req.user!.username, ip: req.ip, details: `${bundle.preKeys.length} pre-keys` });
    res.json({ success: true });
  } catch (err) {
    logger.error({ err, userId: req.user!.id }, 'Upload bundle error');
    res.status(500).json({ error: 'Failed to upload bundle' });
  }
});

router.get('/bundle/:userId', authenticateToken, (req: Request, res: Response) => {
  try {
    const userId = parseInt(req.params['userId'] as string, 10);
    if (isNaN(userId)) {
      res.status(400).json({ error: 'Invalid user ID' });
      return;
    }

    if (userId === req.user!.id) {
      res.status(400).json({ error: 'Cannot fetch your own bundle' });
      return;
    }

    // Rate limit bundle fetches per requester+target to prevent pre-key exhaustion
    const now = Date.now();

    // H5: Per-requester global rate limit (prevents multi-account pre-key exhaustion)
    const requesterKey = `requester:${req.user!.id}`;
    let requesterEntry = bundleFetchCounts.get(requesterKey);
    if (!requesterEntry || now - requesterEntry.windowStart > BUNDLE_FETCH_WINDOW_MS) {
      requesterEntry = { count: 0, windowStart: now };
      bundleFetchCounts.set(requesterKey, requesterEntry);
    }
    requesterEntry.count++;
    if (requesterEntry.count > 50) { // Max 50 total bundle fetches per hour
      res.status(429).json({ error: 'Too many key requests. Try again later.' });
      return;
    }

    // Per-target rate limit (max 3 fetches per target per hour)
    const rateLimitKey = `${req.user!.id}:${userId}`;
    let fetchEntry = bundleFetchCounts.get(rateLimitKey);
    if (!fetchEntry || now - fetchEntry.windowStart > BUNDLE_FETCH_WINDOW_MS) {
      fetchEntry = { count: 0, windowStart: now };
      bundleFetchCounts.set(rateLimitKey, fetchEntry);
    }
    fetchEntry.count++;
    if (fetchEntry.count > BUNDLE_FETCH_LIMIT) {
      res.status(429).json({ error: 'Too many key requests for this user. Try again later.' });
      return;
    }

    const user = stmt.getUserById.get(userId) as Pick<DbUser, 'id' | 'username'> | undefined;
    if (!user) {
      res.status(404).json({ error: 'User not found' });
      return;
    }

    const bundle = getPreKeyBundle(userId);
    if (!bundle) {
      res.status(404).json({ error: 'No pre-key bundle available' });
      return;
    }

    bundle.userId = userId;
    bundle.username = user.username;

    // Include key transparency proof in bundle response
    const keyLogProof = getLatestKeyLogForUser(userId);
    if (keyLogProof) {
      bundle.keyLogProof = keyLogProof;
    }

    // Warn the target user if their pre-keys are running low
    const { count } = stmt.countOneTimePreKeys.get(userId) as DbCount;
    if (count < PREKEY_LOW_THRESHOLD && isOnline(userId)) {
      const ws = getConnection(userId);
      if (ws && ws.readyState === 1) {
        ws.send(JSON.stringify({ type: WS_MSG_TYPE.PREKEY_LOW, remaining: count }));
      }
    }

    res.json(bundle);
  } catch (err) {
    logger.error({ err, userId: req.user!.id }, 'Get bundle error');
    res.status(500).json({ error: 'Failed to fetch bundle' });
  }
});

router.post('/replenish', authenticateToken, (req: Request, res: Response) => {
  try {
    const { preKeys } = req.body as { preKeys?: PreKeyPublic[] };
    if (!Array.isArray(preKeys) || preKeys.length === 0) {
      res.status(400).json({ error: 'preKeys array required' });
      return;
    }
    if (preKeys.length > MAX_PREKEYS_PER_UPLOAD) {
      res.status(400).json({ error: `Maximum ${MAX_PREKEYS_PER_UPLOAD} pre-keys per upload` });
      return;
    }

    for (const pk of preKeys) {
      if (typeof pk.keyId !== 'number' || typeof pk.publicKey !== 'string') {
        res.status(400).json({ error: 'Invalid preKey format' });
        return;
      }
      stmt.insertOneTimePreKey.run(req.user!.id, pk.keyId, pk.publicKey);
    }

    const { count } = stmt.countOneTimePreKeys.get(req.user!.id) as DbCount;
    logger.info({ userId: req.user!.id, added: preKeys.length, total: count }, 'Pre-keys replenished');
    res.json({ success: true, remaining: count });
  } catch (err) {
    logger.error({ err, userId: req.user!.id }, 'Replenish error');
    res.status(500).json({ error: 'Failed to replenish keys' });
  }
});

router.get('/count', authenticateToken, (req: Request, res: Response) => {
  try {
    const { count } = stmt.countOneTimePreKeys.get(req.user!.id) as DbCount;
    res.json({ count });
  } catch (err) {
    logger.error({ err, userId: req.user!.id }, 'Key count error');
    res.status(500).json({ error: 'Failed to get key count' });
  }
});

// Issue a signed sender certificate for sealed sender (IMP-8: dedicated rate limit)
router.post('/sender-cert', authenticateToken, senderCertLimiter, (req: Request, res: Response) => {
  try {
    const identity = stmt.getIdentityKey.get(req.user!.id) as DbIdentityKey | undefined;
    if (!identity) {
      res.status(404).json({ error: 'No identity key registered. Upload a bundle first.' });
      return;
    }

    const cert = issueSenderCertificate(req.user!.id, req.user!.username, identity.identity_key);
    res.json(cert);
  } catch (err) {
    logger.error({ err, userId: req.user!.id }, 'Sender certificate error');
    res.status(500).json({ error: 'Failed to issue sender certificate' });
  }
});

// IMP-3 fix: require authentication to fetch server key (trust anchor endpoint)
router.get('/server-key', authenticateToken, (_req: Request, res: Response) => {
  res.json({ publicKey: getServerPublicKey() });
});

// Key transparency: get a user's full key log history
router.get('/key-log/:userId', authenticateToken, (req: Request, res: Response) => {
  try {
    const userId = parseInt(req.params['userId'] as string, 10);
    if (isNaN(userId)) {
      res.status(400).json({ error: 'Invalid user ID' });
      return;
    }

    const entries = getKeyLogForUser(userId);
    res.json(entries.map(e => ({
      sequence: e.sequence,
      userId: e.user_id,
      identityKey: e.identity_key,
      previousHash: e.previous_hash,
      entryHash: e.entry_hash,
      signature: e.signature,
      timestamp: e.timestamp,
    })));
  } catch (err) {
    logger.error({ err, userId: req.user!.id }, 'Key log fetch error');
    res.status(500).json({ error: 'Failed to fetch key log' });
  }
});

// Key transparency: get recent log entries (for gossip/sync)
router.get('/key-log', authenticateToken, (req: Request, res: Response) => {
  try {
    const after = parseInt(req.query['after'] as string || '0', 10);
    const limit = Math.min(parseInt(req.query['limit'] as string || '100', 10), 1000);

    const entries = getKeyLogRange(after, limit);
    res.json(entries.map(e => ({
      sequence: e.sequence,
      userId: e.user_id,
      identityKey: e.identity_key,
      previousHash: e.previous_hash,
      entryHash: e.entry_hash,
      signature: e.signature,
      timestamp: e.timestamp,
    })));
  } catch (err) {
    logger.error({ err, userId: req.user!.id }, 'Key log range error');
    res.status(500).json({ error: 'Failed to fetch key log' });
  }
});

export default router;
