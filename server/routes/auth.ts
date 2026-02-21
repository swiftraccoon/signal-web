import express, { Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import config from '../config';
import { stmt, deleteUser } from '../db';
import { audit } from '../audit';
import { hash as hashPassword, verify as verifyPassword, needsRehash } from '../hasher';
import { validateRegister, validateLogin } from '../middleware/validate';
import { authLimiter, accountDeleteLimiter } from '../middleware/rateLimiter';
import { authenticateToken } from '../middleware/auth';
import { getConnection, isOnline } from '../ws/connections';
import { createWsTicket } from '../ws/tickets';
import logger from '../logger';
import { incr } from '../metrics';
import type { DbUser, DbRefreshToken } from '../../shared/types';

const router = express.Router();

// Dummy hash for constant-time verification (prevents timing-based user enumeration)
let DUMMY_HASH: string;
void (async () => {
  DUMMY_HASH = await hashPassword('dummy-password-for-timing');
})();

// M8: Add audience claim to JWT for cross-service isolation
function signToken(payload: { id: number | bigint; username: string; token_version: number }, fp: string): string {
  return jwt.sign(
    { id: Number(payload.id), username: payload.username, token_version: payload.token_version, fp },
    config.JWT_SECRET,
    {
      algorithm: config.JWT_ALGORITHM as jwt.Algorithm,
      expiresIn: config.JWT_EXPIRY,
      audience: 'signal-web',
      issuer: 'signal-web',
    } as jwt.SignOptions,
  );
}

function getClientIp(req: Request): string | undefined {
  return req.ip || req.socket.remoteAddress;
}

function computeFingerprint(req: Request): string {
  const ua = req.headers['user-agent'] || '';
  const ip = getClientIp(req) || '';
  // Use /24 subnet for IPv4, /48 for IPv6 (tolerates NAT/CGNAT)
  let subnet = ip;
  if (ip.includes('.')) {
    // IPv4: keep first 3 octets
    subnet = ip.split('.').slice(0, 3).join('.');
  } else if (ip.includes(':')) {
    // IPv6: keep first 3 groups (48 bits)
    subnet = ip.split(':').slice(0, 3).join(':');
  }
  return crypto.createHash('sha256').update(`${ua}|${subnet}`).digest('hex').slice(0, 16);
}

function generateRefreshToken(): string {
  return crypto.randomBytes(48).toString('base64url');
}

function hashToken(token: string): string {
  return crypto.createHash('sha256').update(token).digest('hex');
}

function setRefreshCookie(res: Response, token: string): void {
  const maxAgeMs = config.REFRESH_TOKEN_EXPIRY_DAYS * 86400 * 1000;
  res.cookie('refresh_token', token, {
    httpOnly: true,
    secure: config.IS_PRODUCTION,
    sameSite: 'strict',
    path: '/api/auth',
    maxAge: maxAgeMs,
  });
}

function clearRefreshCookie(res: Response): void {
  res.clearCookie('refresh_token', {
    httpOnly: true,
    secure: config.IS_PRODUCTION,
    sameSite: 'strict',
    path: '/api/auth',
  });
}

// Track recently rotated token hashes for reuse detection (TTL: 24h)
const recentlyRotatedHashes = new Map<string, { userId: number; rotatedAt: number }>();

// Periodic cleanup of stale entries
setInterval(() => {
  const cutoff = Date.now() - 86400000; // 24h
  /* eslint-disable @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-argument -- Map<string, {userId, rotatedAt}> iteration; type not resolved by project service */
  for (const [hash, entry] of recentlyRotatedHashes) {
    if (entry.rotatedAt < cutoff) recentlyRotatedHashes.delete(hash);
  }
  /* eslint-enable @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-argument */
}, 3600000); // Every hour

function issueRefreshToken(userId: number): string {
  // Enforce concurrent session limit
  const countResult = stmt.countUserRefreshTokens.get(userId) as { count: number };
  while (countResult.count >= config.MAX_CONCURRENT_SESSIONS) {
    stmt.deleteOldestRefreshToken.run(userId);
    countResult.count--;
  }

  const token = generateRefreshToken();
  const hash = hashToken(token);
  const expiresAt = Math.floor(Date.now() / 1000) + (config.REFRESH_TOKEN_EXPIRY_DAYS * 86400);
  stmt.createRefreshToken.run(userId, hash, expiresAt);
  return token;
}

router.post('/register', authLimiter, ...validateRegister, async (req: Request, res: Response) => {
  const ip = getClientIp(req);
  try {
    const { username, password } = req.body as { username: string; password: string };

    const existing = stmt.getUserByUsername.get(username) as DbUser | undefined;

    // Always hash even if username exists (prevents timing-based enumeration)
    const hash = await hashPassword(password);

    if (existing) {
      res.status(409).json({ error: 'Username already taken' });
      return;
    }

    const result = stmt.createUser.run(username, hash);

    const token = signToken({ id: result.lastInsertRowid, username, token_version: 1 }, computeFingerprint(req));
    const refreshToken = issueRefreshToken(result.lastInsertRowid as number);

    incr('authSuccess');
    audit('register', { userId: result.lastInsertRowid as number, username, ip });
    logger.info({ username, ip }, 'User registered');

    setRefreshCookie(res, refreshToken);
    res.status(201).json({
      token,
      user: { id: result.lastInsertRowid, username },
    });
  } catch (err) {
    logger.error({ err, ip }, 'Register error');
    res.status(500).json({ error: 'Registration failed' });
  }
});

router.post('/login', authLimiter, ...validateLogin, async (req: Request, res: Response) => {
  const ip = getClientIp(req);
  try {
    const { username, password } = req.body as { username: string; password: string };

    const user = stmt.getUserByUsername.get(username) as DbUser | undefined;

    // Check account lockout
    if (user && user.locked_until) {
      const lockExpiry = new Date(user.locked_until + 'Z');
      if (lockExpiry > new Date()) {
        incr('authFailure');
        audit('login_locked', { userId: user.id, username, ip });
        res.status(429).json({
          error: 'Account temporarily locked due to too many failed attempts. Try again later.',
        });
        return;
      }
      // Lock has expired, reset
      stmt.resetFailedLogins.run(user.id);
    }

    // Always verify to prevent timing-based user enumeration
    const storedHash = user ? user.password : DUMMY_HASH;
    const valid = await verifyPassword(password, storedHash);

    if (!user || !valid) {
      incr('authFailure');

      // C5: Atomic increment + check to prevent TOCTOU race on lockout
      if (user) {
        const result = stmt.incrementFailedLoginsAndGet.get(user.id) as { failed_login_attempts: number } | undefined;
        if (result && result.failed_login_attempts >= config.MAX_FAILED_LOGINS) {
          stmt.lockAccount.run(String(config.LOCKOUT_DURATION_MIN), user.id);
          audit('account_locked', { userId: user.id, username, ip, details: `After ${result.failed_login_attempts} failed attempts` });
          logger.warn({ username, ip, attempts: result.failed_login_attempts }, 'Account locked due to failed login attempts');
        }
      }

      audit('login_failed', { username, ip });
      res.status(401).json({ error: 'Invalid credentials' });
      return;
    }

    // Successful login - reset failed attempts
    if (user.failed_login_attempts > 0) {
      stmt.resetFailedLogins.run(user.id);
    }

    // Opportunistic rehash: upgrade bcrypt -> Argon2id on successful login
    if (needsRehash(user.password)) {
      const newHash = await hashPassword(password);
      stmt.updatePassword.run(newHash, user.id);
      logger.info({ username: user.username }, 'Password hash upgraded to Argon2id');
    }

    const token = signToken({ id: user.id, username: user.username, token_version: user.token_version }, computeFingerprint(req));
    const refreshToken = issueRefreshToken(user.id);

    incr('authSuccess');
    audit('login_success', { userId: user.id, username: user.username, ip });
    logger.info({ username: user.username, ip }, 'User logged in');

    setRefreshCookie(res, refreshToken);
    res.json({
      token,
      user: { id: user.id, username: user.username },
    });
  } catch (err) {
    logger.error({ err, ip }, 'Login error');
    res.status(500).json({ error: 'Login failed' });
  }
});

router.delete('/account', authenticateToken, accountDeleteLimiter, async (req: Request, res: Response) => {
  const ip = getClientIp(req);
  try {
    const { password } = req.body as { password?: string };
    if (!password) {
      res.status(400).json({ error: 'Password required for account deletion' });
      return;
    }

    const user = stmt.getUserByUsername.get(req.user!.username) as DbUser | undefined;
    // Always verify even if user not found (constant-time)
    const storedHash = user ? user.password : DUMMY_HASH;
    const valid = await verifyPassword(password, storedHash);

    if (!user || !valid) {
      res.status(401).json({ error: 'Invalid password' });
      return;
    }

    closeUserConnection(user.id);
    stmt.deleteUserRefreshTokens.run(user.id);
    deleteUser(user.id);
    clearRefreshCookie(res);
    audit('account_deleted', { userId: user.id, username: user.username, ip });
    logger.info({ username: user.username, ip }, 'Account deleted');
    res.json({ success: true });
  } catch (err) {
    logger.error({ err, ip }, 'Delete account error');
    res.status(500).json({ error: 'Account deletion failed' });
  }
});

router.put('/password', authenticateToken, authLimiter, async (req: Request, res: Response) => {
  const ip = getClientIp(req);
  try {
    const { currentPassword, newPassword } = req.body as { currentPassword?: string; newPassword?: string };
    if (!currentPassword || !newPassword) {
      res.status(400).json({ error: 'Current and new password required' });
      return;
    }

    // Argon2id has no practical length limit, but cap at 128 for DoS prevention
    if (newPassword.length < 12 || newPassword.length > 128) {
      res.status(400).json({ error: 'Password must be 12-128 characters' });
      return;
    }
    if (!/[a-z]/.test(newPassword)) {
      res.status(400).json({ error: 'Password must include a lowercase letter' });
      return;
    }
    if (!/[A-Z]/.test(newPassword)) {
      res.status(400).json({ error: 'Password must include an uppercase letter' });
      return;
    }
    if (!/[0-9]/.test(newPassword)) {
      res.status(400).json({ error: 'Password must include a number' });
      return;
    }

    const user = stmt.getUserByUsername.get(req.user!.username) as DbUser | undefined;
    const storedHash = user ? user.password : DUMMY_HASH;
    const valid = await verifyPassword(currentPassword, storedHash);

    if (!user || !valid) {
      res.status(401).json({ error: 'Current password is incorrect' });
      return;
    }

    const newHash = await hashPassword(newPassword);
    stmt.updatePassword.run(newHash, user.id);
    stmt.deleteUserRefreshTokens.run(user.id);
    clearRefreshCookie(res);

    // H1: Close active WebSocket connection after password change
    closeUserConnection(user.id);

    audit('password_changed', { userId: user.id, username: user.username, ip });
    logger.info({ username: user.username, ip }, 'Password changed');

    res.json({ success: true });
  } catch (err) {
    logger.error({ err, ip }, 'Change password error');
    res.status(500).json({ error: 'Password change failed' });
  }
});

// Refresh access token using a valid refresh token (with rotation)
router.post('/refresh', (req: Request, res: Response) => {
  const refreshToken = req.cookies?.refresh_token as string | undefined;
  if (!refreshToken) {
    res.status(400).json({ error: 'Refresh token required' });
    return;
  }
  const hash = hashToken(refreshToken);

  // Check for token reuse after rotation (breach signal)
  const rotatedEntry = recentlyRotatedHashes.get(hash);
  if (rotatedEntry) {
    logger.error('BREACH: Refresh token reused after rotation — invalidating all sessions');
    audit('token_reuse_breach', { details: 'All sessions invalidated' });
    stmt.deleteUserRefreshTokens.run(rotatedEntry.userId);
    recentlyRotatedHashes.delete(hash);
    res.status(401).json({ error: 'Session compromised — all sessions invalidated' });
    return;
  }

  const stored = stmt.getRefreshToken.get(hash) as DbRefreshToken | undefined;
  if (!stored) {
    res.status(401).json({ error: 'Invalid or expired refresh token' });
    return;
  }
  // Rotate: delete old token and track it for breach detection
  stmt.deleteRefreshToken.run(hash);
  recentlyRotatedHashes.set(hash, { userId: stored.user_id, rotatedAt: Date.now() });

  const user = stmt.getUserById.get(stored.user_id) as { id: number; username: string; token_version: number } | undefined;
  if (!user) {
    res.status(401).json({ error: 'User not found' });
    return;
  }
  const accessToken = signToken({ id: user.id, username: user.username, token_version: user.token_version }, computeFingerprint(req));
  const newRefreshToken = issueRefreshToken(user.id);
  setRefreshCookie(res, newRefreshToken);

  res.json({ token: accessToken, user });
});

// Logout: invalidate the provided refresh token
router.post('/logout', authenticateToken, (req: Request, res: Response) => {
  const refreshToken = req.cookies?.refresh_token as string | undefined;
  if (refreshToken) {
    stmt.deleteRefreshToken.run(hashToken(refreshToken));
  }
  clearRefreshCookie(res);
  res.json({ success: true });
});

// Issue a short-lived one-time ticket for WebSocket connection
router.post('/ws-ticket', authenticateToken, (req: Request, res: Response) => {
  const ticket = createWsTicket(req.user!.id, req.user!.username);
  res.json({ ticket });
});

// Close WS connection on account deletion or password change
function closeUserConnection(userId: number): void {
  if (isOnline(userId)) {
    const ws = getConnection(userId);
    if (ws) ws.close(4002, 'Session invalidated');
  }
}

export default router;
