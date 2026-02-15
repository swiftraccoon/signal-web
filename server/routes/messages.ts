import express, { Request, Response } from 'express';
import { authenticateToken } from '../middleware/auth';
import { stmt } from '../db';
import logger from '../logger';
import type { DbPendingMessageRow, PendingMessage } from '../../shared/types';

const router = express.Router();

router.get('/pending', authenticateToken, (req: Request, res: Response) => {
  try {
    const messages = stmt.getPendingMessages.all(req.user!.id) as DbPendingMessageRow[];

    // Do NOT mark as delivered here. Include dbId so the client can ACK
    // each message via WebSocket after successful processing. This prevents
    // message loss if the HTTP response fails to reach the client.

    logger.debug({ userId: req.user!.id, count: messages.length }, 'Pending messages fetched');

    const response: PendingMessage[] = messages.map(m => ({
      from: m.sender_username,
      fromId: m.sender_id,
      message: { type: m.type, body: m.body },
      timestamp: m.timestamp,
      dbId: m.id,
    }));

    res.json(response);
  } catch (err) {
    logger.error({ err, userId: req.user!.id }, 'Pending messages error');
    res.status(500).json({ error: 'Failed to fetch messages' });
  }
});

export default router;
