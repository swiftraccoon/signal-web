const express = require('express');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const config = require('../config');
const { stmt, deleteUser, audit } = require('../db');
const { validateRegister, validateLogin } = require('../middleware/validate');
const { authLimiter } = require('../middleware/rateLimiter');
const { authenticateToken } = require('../middleware/auth');
const { removeConnection, getConnection, isOnline } = require('../ws/connections');
const logger = require('../logger');
const { incr } = require('../metrics');

const router = express.Router();

// Dummy hash for constant-time login (prevents timing-based user enumeration)
const DUMMY_HASH = bcrypt.hashSync('dummy-password-for-timing', config.BCRYPT_ROUNDS);

// One-time WS connection tickets (avoids JWT in URL query string)
const wsTickets = new Map(); // ticket -> { userId, username, expiresAt }
const WS_TICKET_TTL_MS = 30000; // 30 seconds

// Periodic cleanup of expired tickets (prevents memory leak)
setInterval(() => {
  const now = Date.now();
  for (const [t, v] of wsTickets) {
    if (v.expiresAt < now) wsTickets.delete(t);
  }
}, 60000);

function createWsTicket(userId, username) {
  const ticket = crypto.randomBytes(32).toString('hex');
  wsTickets.set(ticket, {
    userId,
    username,
    expiresAt: Date.now() + WS_TICKET_TTL_MS,
  });
  return ticket;
}

function consumeWsTicket(ticket) {
  const entry = wsTickets.get(ticket);
  if (!entry) return null;
  wsTickets.delete(ticket); // one-time use
  if (entry.expiresAt < Date.now()) return null; // expired
  return entry;
}

function signToken(payload) {
  return jwt.sign(payload, config.JWT_SECRET, {
    algorithm: config.JWT_ALGORITHM,
    expiresIn: config.JWT_EXPIRY,
  });
}

function getClientIp(req) {
  return req.ip || req.socket.remoteAddress;
}

router.post('/register', authLimiter, validateRegister, async (req, res) => {
  const ip = getClientIp(req);
  try {
    const { username, password } = req.body;

    const existing = stmt.getUserByUsername.get(username);
    if (existing) {
      return res.status(409).json({ error: 'Username already taken' });
    }

    const hash = await bcrypt.hash(password, config.BCRYPT_ROUNDS);
    const result = stmt.createUser.run(username, hash);

    const token = signToken({ id: result.lastInsertRowid, username });

    incr('authSuccess');
    audit('register', { userId: result.lastInsertRowid, username, ip });
    logger.info({ username, ip }, 'User registered');

    res.status(201).json({
      token,
      user: { id: result.lastInsertRowid, username },
    });
  } catch (err) {
    logger.error({ err, ip }, 'Register error');
    res.status(500).json({ error: 'Registration failed' });
  }
});

router.post('/login', authLimiter, validateLogin, async (req, res) => {
  const ip = getClientIp(req);
  try {
    const { username, password } = req.body;

    const user = stmt.getUserByUsername.get(username);

    // Check account lockout
    if (user && user.locked_until) {
      const lockExpiry = new Date(user.locked_until + 'Z');
      if (lockExpiry > new Date()) {
        incr('authFailure');
        audit('login_locked', { userId: user.id, username, ip });
        return res.status(429).json({
          error: 'Account temporarily locked due to too many failed attempts. Try again later.',
        });
      }
      // Lock has expired, reset
      stmt.resetFailedLogins.run(user.id);
    }

    // Always run bcrypt.compare to prevent timing-based user enumeration
    const hash = user ? user.password : DUMMY_HASH;
    const valid = await bcrypt.compare(password, hash);

    if (!user || !valid) {
      incr('authFailure');

      if (user) {
        stmt.incrementFailedLogins.run(user.id);
        const updated = stmt.getUserByUsername.get(username);
        if (updated.failed_login_attempts >= config.MAX_FAILED_LOGINS) {
          stmt.lockAccount.run(String(config.LOCKOUT_DURATION_MIN), user.id);
          audit('account_locked', { userId: user.id, username, ip, details: `After ${updated.failed_login_attempts} failed attempts` });
          logger.warn({ username, ip, attempts: updated.failed_login_attempts }, 'Account locked due to failed login attempts');
        }
      }

      audit('login_failed', { username, ip });
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Successful login - reset failed attempts
    if (user.failed_login_attempts > 0) {
      stmt.resetFailedLogins.run(user.id);
    }

    const token = signToken({ id: user.id, username: user.username });

    incr('authSuccess');
    audit('login_success', { userId: user.id, username: user.username, ip });
    logger.info({ username: user.username, ip }, 'User logged in');

    res.json({
      token,
      user: { id: user.id, username: user.username },
    });
  } catch (err) {
    logger.error({ err, ip }, 'Login error');
    res.status(500).json({ error: 'Login failed' });
  }
});

router.delete('/account', authenticateToken, async (req, res) => {
  const ip = getClientIp(req);
  try {
    const { password } = req.body;
    if (!password) {
      return res.status(400).json({ error: 'Password required for account deletion' });
    }

    const user = stmt.getUserByUsername.get(req.user.username);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) {
      return res.status(401).json({ error: 'Invalid password' });
    }

    closeUserConnection(user.id);
    deleteUser(user.id);
    audit('account_deleted', { userId: user.id, username: user.username, ip });
    logger.info({ username: user.username, ip }, 'Account deleted');
    res.json({ success: true });
  } catch (err) {
    logger.error({ err, ip }, 'Delete account error');
    res.status(500).json({ error: 'Account deletion failed' });
  }
});

router.put('/password', authenticateToken, async (req, res) => {
  const ip = getClientIp(req);
  try {
    const { currentPassword, newPassword } = req.body;
    if (!currentPassword || !newPassword) {
      return res.status(400).json({ error: 'Current and new password required' });
    }

    if (newPassword.length < 12) {
      return res.status(400).json({ error: 'New password must be at least 12 characters' });
    }
    if (!/[a-z]/.test(newPassword)) {
      return res.status(400).json({ error: 'Password must include a lowercase letter' });
    }
    if (!/[A-Z]/.test(newPassword)) {
      return res.status(400).json({ error: 'Password must include an uppercase letter' });
    }
    if (!/[0-9]/.test(newPassword)) {
      return res.status(400).json({ error: 'Password must include a number' });
    }

    const user = stmt.getUserByUsername.get(req.user.username);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const valid = await bcrypt.compare(currentPassword, user.password);
    if (!valid) {
      return res.status(401).json({ error: 'Current password is incorrect' });
    }

    const hash = await bcrypt.hash(newPassword, config.BCRYPT_ROUNDS);
    stmt.updatePassword.run(hash, user.id);

    audit('password_changed', { userId: user.id, username: user.username, ip });
    logger.info({ username: user.username, ip }, 'Password changed');

    res.json({ success: true });
  } catch (err) {
    logger.error({ err, ip }, 'Change password error');
    res.status(500).json({ error: 'Password change failed' });
  }
});

// Issue a short-lived one-time ticket for WebSocket connection
router.post('/ws-ticket', authenticateToken, (req, res) => {
  const ticket = createWsTicket(req.user.id, req.user.username);
  res.json({ ticket });
});

// Close WS connection on account deletion
function closeUserConnection(userId) {
  if (isOnline(userId)) {
    const ws = getConnection(userId);
    if (ws) ws.close(4002, 'Account deleted');
  }
}

module.exports = router;
module.exports.consumeWsTicket = consumeWsTicket;
