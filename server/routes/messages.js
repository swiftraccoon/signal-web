const express = require('express');
const { authenticateToken } = require('../middleware/auth');
const { stmt } = require('../db');
const logger = require('../logger');

const router = express.Router();

router.get('/pending', authenticateToken, (req, res) => {
  try {
    const messages = stmt.getPendingMessages.all(req.user.id);

    // Do NOT mark as delivered here. Include dbId so the client can ACK
    // each message via WebSocket after successful processing. This prevents
    // message loss if the HTTP response fails to reach the client.

    logger.debug({ userId: req.user.id, count: messages.length }, 'Pending messages fetched');

    res.json(messages.map(m => ({
      from: m.sender_username,
      fromId: m.sender_id,
      message: { type: m.type, body: m.body },
      timestamp: m.timestamp,
      dbId: m.id, // for client-side ACK
    })));
  } catch (err) {
    logger.error({ err, userId: req.user.id }, 'Pending messages error');
    res.status(500).json({ error: 'Failed to fetch messages' });
  }
});

module.exports = router;
