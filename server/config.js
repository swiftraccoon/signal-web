require('dotenv').config();
const crypto = require('crypto');

const isProduction = process.env.NODE_ENV === 'production';

// Generate a random secret if none provided (safe for single-instance dev)
const defaultSecret = crypto.randomBytes(64).toString('hex');

if (!process.env.JWT_SECRET) {
  if (isProduction) {
    console.error('FATAL: JWT_SECRET must be set in production. Exiting.');
    process.exit(1);
  }
  console.warn('WARNING: JWT_SECRET not set. Using random secret (sessions will not survive restarts).');
}

const PORT = parseInt(process.env.PORT, 10) || 3000;
if (isNaN(PORT) || PORT < 1 || PORT > 65535) {
  console.error('FATAL: Invalid PORT value. Must be 1-65535.');
  process.exit(1);
}

module.exports = {
  PORT,
  JWT_SECRET: process.env.JWT_SECRET || defaultSecret,
  JWT_ALGORITHM: 'HS256',
  DB_PATH: process.env.DB_PATH || './signal-web.db',
  BCRYPT_ROUNDS: 12,
  JWT_EXPIRY: '24h',
  IS_PRODUCTION: isProduction,
  // Account lockout settings
  MAX_FAILED_LOGINS: 10,
  LOCKOUT_DURATION_MIN: 15,
};
