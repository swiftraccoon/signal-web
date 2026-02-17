import express, { Request, Response } from 'express';
import { authenticateToken } from '../middleware/auth';
import { stmt } from '../db';
import logger from '../logger';
import type { DbPendingMessageRow, PendingMessage, PendingSealedMessage } from '../../shared/types';

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

// Fetch pending sealed messages (server has no idea who sent them)
router.get('/pending-sealed', authenticateToken, (req: Request, res: Response) => {
  try {
    const rows = stmt.getPendingSealedMessages.all(req.user!.id) as { id: number; envelope: string; timestamp: string }[];

    const response: PendingSealedMessage[] = rows.map(r => ({
      envelope: JSON.parse(r.envelope) as PendingSealedMessage['envelope'],
      timestamp: r.timestamp,
      dbId: r.id,
    }));

    logger.debug({ userId: req.user!.id, count: rows.length }, 'Pending sealed messages fetched');
    res.json(response);
  } catch (err) {
    logger.error({ err, userId: req.user!.id }, 'Pending sealed messages error');
    res.status(500).json({ error: 'Failed to fetch sealed messages' });
  }
});

export default router;
