import express, { Request, Response } from 'express';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import config from '../config';
import { stmt, deleteUser } from '../db';
import { audit } from '../audit';
import { validateRegister, validateLogin } from '../middleware/validate';
import { authLimiter, accountDeleteLimiter } from '../middleware/rateLimiter';
import { authenticateToken } from '../middleware/auth';
import { getConnection, isOnline } from '../ws/connections';
import { createWsTicket } from '../ws/tickets';
import logger from '../logger';
import { incr } from '../metrics';
import type { DbUser, DbRefreshToken } from '../../shared/types';

const router = express.Router();

// Dummy hash for constant-time login (prevents timing-based user enumeration)
const DUMMY_HASH = bcrypt.hashSync('dummy-password-for-timing', config.BCRYPT_ROUNDS);

// M8: Add audience claim to JWT for cross-service isolation
function signToken(payload: { id: number | bigint; username: string; token_version: number }): string {
  return jwt.sign(
    { id: Number(payload.id), username: payload.username, token_version: payload.token_version },
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

function generateRefreshToken(): string {
  return crypto.randomBytes(48).toString('base64url');
}

function hashToken(token: string): string {
  return crypto.createHash('sha256').update(token).digest('hex');
}

function issueRefreshToken(userId: number): string {
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

    // M1: Always run bcrypt even if username exists (prevents timing-based enumeration)
    const hash = await bcrypt.hash(password, config.BCRYPT_ROUNDS);

    if (existing) {
      res.status(409).json({ error: 'Username already taken' });
      return;
    }

    const result = stmt.createUser.run(username, hash);

    const token = signToken({ id: result.lastInsertRowid, username, token_version: 1 });
    const refreshToken = issueRefreshToken(result.lastInsertRowid as number);

    incr('authSuccess');
    audit('register', { userId: result.lastInsertRowid as number, username, ip });
    logger.info({ username, ip }, 'User registered');

    res.status(201).json({
      token,
      refreshToken,
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

    // Always run bcrypt.compare to prevent timing-based user enumeration
    const hash = user ? user.password : DUMMY_HASH;
    const valid = await bcrypt.compare(password, hash);

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

    const token = signToken({ id: user.id, username: user.username, token_version: user.token_version });
    const refreshToken = issueRefreshToken(user.id);

    incr('authSuccess');
    audit('login_success', { userId: user.id, username: user.username, ip });
    logger.info({ username: user.username, ip }, 'User logged in');

    res.json({
      token,
      refreshToken,
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
    // Always run bcrypt even if user not found (constant-time)
    const hash = user ? user.password : DUMMY_HASH;
    const valid = await bcrypt.compare(password, hash);

    if (!user || !valid) {
      res.status(401).json({ error: 'Invalid password' });
      return;
    }

    closeUserConnection(user.id);
    stmt.deleteUserRefreshTokens.run(user.id);
    deleteUser(user.id);
    audit('account_deleted', { userId: user.id, username: user.username, ip });
    logger.info({ username: user.username, ip }, 'Account deleted');
    res.json({ success: true });
  } catch (err) {
    logger.error({ err, ip }, 'Delete account error');
    res.status(500).json({ error: 'Account deletion failed' });
  }
});

// M9: Add authLimiter to password change endpoint
router.put('/password', authenticateToken, authLimiter, async (req: Request, res: Response) => {
  const ip = getClientIp(req);
  try {
    const { currentPassword, newPassword } = req.body as { currentPassword?: string; newPassword?: string };
    if (!currentPassword || !newPassword) {
      res.status(400).json({ error: 'Current and new password required' });
      return;
    }

    // H4: Enforce max password length (bcrypt truncates at 72 bytes)
    if (newPassword.length < 12 || newPassword.length > 72) {
      res.status(400).json({ error: 'Password must be 12-72 characters' });
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
    // Always run bcrypt even if user not found (constant-time)
    const hash = user ? user.password : DUMMY_HASH;
    const valid = await bcrypt.compare(currentPassword, hash);

    if (!user || !valid) {
      res.status(401).json({ error: 'Current password is incorrect' });
      return;
    }

    const newHash = await bcrypt.hash(newPassword, config.BCRYPT_ROUNDS);
    stmt.updatePassword.run(newHash, user.id);
    stmt.deleteUserRefreshTokens.run(user.id);

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
  const { refreshToken } = req.body as { refreshToken?: string };
  if (!refreshToken) {
    res.status(400).json({ error: 'Refresh token required' });
    return;
  }
  const hash = hashToken(refreshToken);
  const stored = stmt.getRefreshToken.get(hash) as DbRefreshToken | undefined;
  if (!stored) {
    res.status(401).json({ error: 'Invalid or expired refresh token' });
    return;
  }
  // Rotate: delete old token
  stmt.deleteRefreshToken.run(hash);
  const user = stmt.getUserById.get(stored.user_id) as { id: number; username: string; token_version: number } | undefined;
  if (!user) {
    res.status(401).json({ error: 'User not found' });
    return;
  }
  const accessToken = signToken({ id: user.id, username: user.username, token_version: user.token_version });
  const newRefreshToken = issueRefreshToken(user.id);
  res.json({ token: accessToken, refreshToken: newRefreshToken, user });
});

// Logout: invalidate the provided refresh token
router.post('/logout', authenticateToken, (req: Request, res: Response) => {
  const { refreshToken } = req.body as { refreshToken?: string };
  if (refreshToken) {
    stmt.deleteRefreshToken.run(hashToken(refreshToken));
  }
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
