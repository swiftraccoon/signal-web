import dotenv from 'dotenv';
import crypto from 'crypto';
import type { ServerConfig } from '../shared/types';

dotenv.config();

const isProduction = process.env.NODE_ENV === 'production';

// Generate a random secret if none provided (safe for single-instance dev)
const defaultSecret = crypto.randomBytes(64).toString('hex');

if (!process.env.JWT_SECRET) {
  if (isProduction) {
    console.error('FATAL: JWT_SECRET must be set in production. Exiting.');
    process.exit(1);
  }
  console.warn('WARNING: JWT_SECRET not set. Using random secret (sessions will not survive restarts).');
} else if (isProduction && process.env.JWT_SECRET.length < 64) {
  console.error('FATAL: JWT_SECRET must be at least 64 characters in production. Exiting.');
  process.exit(1);
}

const PORT = parseInt(process.env.PORT ?? '', 10) || 3000;
if (isNaN(PORT) || PORT < 1 || PORT > 65535) {
  console.error('FATAL: Invalid PORT value. Must be 1-65535.');
  process.exit(1);
}

const LOCKOUT_DURATION_MIN = parseInt(process.env.LOCKOUT_DURATION_MIN || '15', 10);
if (isNaN(LOCKOUT_DURATION_MIN) || LOCKOUT_DURATION_MIN < 1 || LOCKOUT_DURATION_MIN > 1440) {
  console.error('FATAL: LOCKOUT_DURATION_MIN must be 1-1440.');
  process.exit(1);
}

const config: ServerConfig = {
  PORT,
  JWT_SECRET: process.env.JWT_SECRET || defaultSecret,
  JWT_ALGORITHM: 'HS256',
  DB_PATH: process.env.DB_PATH || './signal-web.db',
  BCRYPT_ROUNDS: parseInt(process.env.BCRYPT_ROUNDS || '13', 10),
  JWT_EXPIRY: '15m',
  ACCESS_TOKEN_EXPIRY: '15m',
  REFRESH_TOKEN_EXPIRY_DAYS: 7,
  IS_PRODUCTION: isProduction,
  MAX_FAILED_LOGINS: 10,
  LOCKOUT_DURATION_MIN,
  REDIS_URL: process.env.REDIS_URL || null,
  ALLOWED_WS_ORIGINS: process.env.ALLOWED_WS_ORIGINS
    ? process.env.ALLOWED_WS_ORIGINS.split(',')
    : isProduction
      ? [] // Must be configured in production
      : [`http://localhost:${parseInt(process.env.PORT ?? '', 10) || 3000}`, `http://127.0.0.1:${parseInt(process.env.PORT ?? '', 10) || 3000}`],
};

export = config;
