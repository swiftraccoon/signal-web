const express = require('express');
const { authenticateToken } = require('../middleware/auth');
const { stmt, getPreKeyBundle, uploadBundle, audit } = require('../db');
const { PREKEY_LOW_THRESHOLD, WS_MSG_TYPE } = require('../../shared/constants');
const { getConnection, isOnline } = require('../ws/connections');
const logger = require('../logger');

const router = express.Router();

const MAX_PREKEYS_PER_UPLOAD = 200;

router.put('/bundle', authenticateToken, (req, res) => {
  try {
    const bundle = req.body;

    // Validate required fields exist and have correct types
    if (typeof bundle.registrationId !== 'number' || bundle.registrationId < 1 || bundle.registrationId > 0x3FFF) {
      return res.status(400).json({ error: 'Invalid registrationId' });
    }
    if (typeof bundle.identityKey !== 'string' || bundle.identityKey.length === 0 || bundle.identityKey.length > 100) {
      return res.status(400).json({ error: 'Invalid identityKey' });
    }
    if (!bundle.signedPreKey || typeof bundle.signedPreKey.keyId !== 'number'
        || typeof bundle.signedPreKey.publicKey !== 'string' || typeof bundle.signedPreKey.signature !== 'string') {
      return res.status(400).json({ error: 'Invalid signedPreKey' });
    }
    if (!Array.isArray(bundle.preKeys)) {
      return res.status(400).json({ error: 'preKeys must be an array' });
    }
    if (bundle.preKeys.length > MAX_PREKEYS_PER_UPLOAD) {
      return res.status(400).json({ error: `Maximum ${MAX_PREKEYS_PER_UPLOAD} pre-keys per upload` });
    }
    // Validate each preKey
    for (const pk of bundle.preKeys) {
      if (typeof pk.keyId !== 'number' || typeof pk.publicKey !== 'string') {
        return res.status(400).json({ error: 'Invalid preKey format' });
      }
    }

    uploadBundle(req.user.id, bundle);
    audit('bundle_uploaded', { userId: req.user.id, username: req.user.username, ip: req.ip, details: `${bundle.preKeys.length} pre-keys` });
    res.json({ success: true });
  } catch (err) {
    logger.error({ err, userId: req.user.id }, 'Upload bundle error');
    res.status(500).json({ error: 'Failed to upload bundle' });
  }
});

router.get('/bundle/:userId', authenticateToken, (req, res) => {
  try {
    const userId = parseInt(req.params.userId, 10);
    if (isNaN(userId)) {
      return res.status(400).json({ error: 'Invalid user ID' });
    }

    if (userId === req.user.id) {
      return res.status(400).json({ error: 'Cannot fetch your own bundle' });
    }

    const user = stmt.getUserById.get(userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const bundle = getPreKeyBundle(userId);
    if (!bundle) {
      return res.status(404).json({ error: 'No pre-key bundle available' });
    }

    bundle.userId = userId;
    bundle.username = user.username;

    // Warn the target user if their pre-keys are running low
    const { count } = stmt.countOneTimePreKeys.get(userId);
    if (count < PREKEY_LOW_THRESHOLD && isOnline(userId)) {
      const ws = getConnection(userId);
      if (ws && ws.readyState === 1) {
        ws.send(JSON.stringify({ type: WS_MSG_TYPE.PREKEY_LOW, remaining: count }));
      }
    }

    res.json(bundle);
  } catch (err) {
    logger.error({ err, userId: req.user.id }, 'Get bundle error');
    res.status(500).json({ error: 'Failed to fetch bundle' });
  }
});

router.post('/replenish', authenticateToken, (req, res) => {
  try {
    const { preKeys } = req.body;
    if (!Array.isArray(preKeys) || preKeys.length === 0) {
      return res.status(400).json({ error: 'preKeys array required' });
    }
    if (preKeys.length > MAX_PREKEYS_PER_UPLOAD) {
      return res.status(400).json({ error: `Maximum ${MAX_PREKEYS_PER_UPLOAD} pre-keys per upload` });
    }

    for (const pk of preKeys) {
      if (typeof pk.keyId !== 'number' || typeof pk.publicKey !== 'string') {
        return res.status(400).json({ error: 'Invalid preKey format' });
      }
      stmt.insertOneTimePreKey.run(req.user.id, pk.keyId, pk.publicKey);
    }

    const { count } = stmt.countOneTimePreKeys.get(req.user.id);
    logger.info({ userId: req.user.id, added: preKeys.length, total: count }, 'Pre-keys replenished');
    res.json({ success: true, remaining: count });
  } catch (err) {
    logger.error({ err, userId: req.user.id }, 'Replenish error');
    res.status(500).json({ error: 'Failed to replenish keys' });
  }
});

router.get('/count', authenticateToken, (req, res) => {
  try {
    const { count } = stmt.countOneTimePreKeys.get(req.user.id);
    res.json({ count });
  } catch (err) {
    logger.error({ err, userId: req.user.id }, 'Key count error');
    res.status(500).json({ error: 'Failed to get key count' });
  }
});

module.exports = router;
