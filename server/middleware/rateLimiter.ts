import rateLimit from 'express-rate-limit';
import RedisStore from 'rate-limit-redis';
import { getRedis } from '../redis';
import type { Store } from 'express-rate-limit';

function createRedisStore(prefix: string): Store | undefined {
  const redis = getRedis();
  if (!redis) return undefined;

  return new RedisStore({
    sendCommand: (...args: string[]) => redis.call(args[0]!, ...args.slice(1)) as Promise<
      boolean | number | string | (boolean | number | string)[]
    >,
    prefix: `rl:${prefix}:`,
  });
}

const authLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 5,
  message: { error: 'Too many attempts, try again later' },
  standardHeaders: true,
  legacyHeaders: false,
  store: createRedisStore('auth'),
});

const generalLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 100,
  message: { error: 'Too many requests, try again later' },
  standardHeaders: true,
  legacyHeaders: false,
  store: createRedisStore('general'),
});

const accountDeleteLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 3,
  message: { error: 'Too many account deletion attempts, try again later' },
  standardHeaders: true,
  legacyHeaders: false,
  store: createRedisStore('account-delete'),
});

// IMP-8: dedicated rate limit for sender certificate issuance
const senderCertLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: 'Too many certificate requests, try again later' },
  standardHeaders: true,
  legacyHeaders: false,
  store: createRedisStore('sender-cert'),
});

const cspReportLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  message: '',
  standardHeaders: false,
  legacyHeaders: false,
  store: createRedisStore('csp-report'),
});

export { authLimiter, generalLimiter, accountDeleteLimiter, senderCertLimiter, cspReportLimiter };
