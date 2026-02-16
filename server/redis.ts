import Redis from 'ioredis';
import config from './config';
import logger from './logger';

let redis: Redis | null = null;

if (config.REDIS_URL) {
  redis = new Redis(config.REDIS_URL, {
    maxRetriesPerRequest: 3,
    lazyConnect: true,
    enableReadyCheck: true,
  });
  redis.on('error', (err: Error) => {
    logger.error({ err }, 'Redis connection error');
  });
  redis.on('connect', () => {
    logger.info('Redis connected');
  });
  redis.connect().catch((err: Error) => {
    logger.warn({ err }, 'Redis unavailable, falling back to in-memory rate limiting');
    redis = null;
  });
} else {
  logger.info('No REDIS_URL configured, using in-memory rate limiting');
}

export function getRedis(): Redis | null {
  return redis;
}
