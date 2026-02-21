import jwt from 'jsonwebtoken';
import crypto from 'crypto';
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
      issuer: 'signal-web',
    }) as JwtTokenPayload;

    // Session fingerprinting: reject tokens used from different device/network
    if (payload.fp) {
      const ua = req.headers['user-agent'] || '';
      const ip = req.ip || req.socket.remoteAddress || '';
      let subnet = ip;
      if (ip.includes('.')) {
        subnet = ip.split('.').slice(0, 3).join('.');
      } else if (ip.includes(':')) {
        subnet = ip.split(':').slice(0, 3).join(':');
      }
      const currentFp = crypto.createHash('sha256').update(`${ua}|${subnet}`).digest('hex').slice(0, 16);
      if (currentFp !== payload.fp) {
        res.status(401).json({ error: 'Session fingerprint mismatch' });
        return;
      }
    }

    // Check token_version — immediate revocation on password change
    const user = stmt.getUserByUsername.get(payload.username) as DbUser | undefined;
    if (!user) {
      res.status(401).json({ error: 'User not found' });
      return;
    }
    if (payload.token_version !== undefined && payload.token_version !== user.token_version) {
      res.status(401).json({ error: 'Token revoked' });
      return;
    }

    req.user = { id: payload.id, username: payload.username };
    next();
  } catch {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
}

export { authenticateToken };
