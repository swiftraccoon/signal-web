const jwt = require('jsonwebtoken');
const config = require('../config');
const { stmt } = require('../db');

function authenticateToken(req, res, next) {
  const header = req.headers.authorization;
  const token = header && header.startsWith('Bearer ') ? header.slice(7) : null;

  if (!token) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  try {
    const payload = jwt.verify(token, config.JWT_SECRET, {
      algorithms: [config.JWT_ALGORITHM],
    });

    // Check if password was changed after this token was issued
    const user = stmt.getUserByUsername.get(payload.username);
    if (user && user.password_changed_at) {
      const changedAt = Math.floor(new Date(user.password_changed_at + 'Z').getTime() / 1000);
      if (payload.iat && payload.iat < changedAt) {
        return res.status(401).json({ error: 'Token invalidated by password change' });
      }
    }

    req.user = { id: payload.id, username: payload.username };
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

module.exports = { authenticateToken };
