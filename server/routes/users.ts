import express, { Request, Response } from 'express';
import { authenticateToken } from '../middleware/auth';
import { validateSearch } from '../middleware/validate';
import { stmt } from '../db';
import logger from '../logger';
import type { ApiUser } from '../../shared/types';

const router = express.Router();

// Escape SQL LIKE wildcards to prevent pattern injection
function escapeLike(str: string): string {
  return str.replace(/[%_\\]/g, '\\$&');
}

router.get('/', authenticateToken, ...validateSearch, (req: Request, res: Response) => {
  try {
    const search = escapeLike(req.query.search as string);
    const users = stmt.searchUsers.all(`%${search}%`) as ApiUser[];
    const filtered = users.filter(u => u.id !== req.user!.id);
    res.json(filtered);
  } catch (err) {
    logger.error({ err, userId: req.user!.id }, 'Search error');
    res.status(500).json({ error: 'Search failed' });
  }
});

export default router;
