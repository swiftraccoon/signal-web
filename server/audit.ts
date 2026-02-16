import crypto from 'crypto';
import logger from './logger';
import config from './config';
import type { AuditOptions } from '../shared/types';

const auditLogger = logger.child({ component: 'audit' });

function computeHmac(event: string, timestamp: string, data: string): string {
  if (!config.AUDIT_SECRET) return '';
  return crypto.createHmac('sha256', config.AUDIT_SECRET)
    .update(`${timestamp}:${event}:${data}`)
    .digest('hex');
}

export function audit(event: string, opts: AuditOptions = {}): void {
  const timestamp = new Date().toISOString();
  const data = JSON.stringify({
    userId: opts.userId ?? null,
    username: opts.username ?? null,
    ip: opts.ip ?? null,
    details: opts.details ?? null,
  });

  const hmac = computeHmac(event, timestamp, data);

  auditLogger.info({
    event,
    timestamp,
    userId: opts.userId ?? null,
    username: opts.username ?? null,
    ip: opts.ip ?? null,
    details: opts.details ?? null,
    hmac,
  }, `audit:${event}`);
}
