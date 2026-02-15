import jwt from 'jsonwebtoken';
import { Request, Response, NextFunction } from 'express';
import config from '../config';
import { stmt } from '../db';
import type { JwtTokenPayload, DbUser } from '../../shared/types';

function authenticateToken(req: Request, res: Response, next: NextFunction): void {
  const header = req.headers.authorization;
  const token = header && header.startsWith('Bearer ') ? header.slice(7) : null;

  if (!token) {
    res.status(401).json({ error: 'Authentication required' });
    return;
  }

  try {
    const payload = jwt.verify(token, config.JWT_SECRET, {
      algorithms: [config.JWT_ALGORITHM as jwt.Algorithm],
      audience: 'signal-web',
    }) as JwtTokenPayload;

    // Check if password was changed after this token was issued
    const user = stmt.getUserByUsername.get(payload.username) as DbUser | undefined;
    if (user && user.password_changed_at) {
      const changedAt = Math.floor(new Date(user.password_changed_at + 'Z').getTime() / 1000);
      if (payload.iat && payload.iat < changedAt) {
        res.status(401).json({ error: 'Token invalidated by password change' });
        return;
      }
    }

    req.user = { id: payload.id, username: payload.username };
    next();
  } catch {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
}

export { authenticateToken };
