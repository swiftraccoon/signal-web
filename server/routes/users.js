const express = require('express');
const { authenticateToken } = require('../middleware/auth');
const { validateSearch } = require('../middleware/validate');
const { stmt } = require('../db');
const logger = require('../logger');

const router = express.Router();

// Escape SQL LIKE wildcards to prevent pattern injection
function escapeLike(str) {
  return str.replace(/[%_\\]/g, '\\$&');
}

router.get('/', authenticateToken, validateSearch, (req, res) => {
  try {
    const search = escapeLike(req.query.search);
    const users = stmt.searchUsers.all(`%${search}%`);
    const filtered = users.filter(u => u.id !== req.user.id);
    res.json(filtered);
  } catch (err) {
    logger.error({ err, userId: req.user.id }, 'Search error');
    res.status(500).json({ error: 'Search failed' });
  }
});

module.exports = router;
