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

export { authLimiter, generalLimiter, accountDeleteLimiter };
