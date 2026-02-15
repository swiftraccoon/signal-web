import type { MetricsCounters, MetricsKey, MetricsSnapshot } from '../shared/types';

// Simple in-process metrics tracking
const metrics: MetricsCounters = {
  httpRequests: 0,
  httpErrors: 0,
  wsConnections: 0,
  wsMessagesIn: 0,
  wsMessagesOut: 0,
  dbQueries: 0,
  dbSlowQueries: 0,
  messagesStored: 0,
  messagesDelivered: 0,
  authSuccess: 0,
  authFailure: 0,
  startedAt: Date.now(),
};

interface RequestDurationEntry {
  count: number;
  totalMs: number;
  maxMs: number;
  p99: number[];
}

// Track request durations by endpoint (rolling window)
const requestDurations: Record<string, RequestDurationEntry> = {};
const DB_SLOW_THRESHOLD_MS = 50;

function incr(key: MetricsKey, amount = 1): void {
  metrics[key] = (metrics[key] || 0) + amount;
}

const MAX_TRACKED_ENDPOINTS = 200;

function trackRequestDuration(method: string, path: string, durationMs: number): void {
  const key = `${method} ${path}`;
  if (!requestDurations[key]) {
    // Cap the number of tracked endpoints to prevent memory exhaustion
    if (Object.keys(requestDurations).length >= MAX_TRACKED_ENDPOINTS) return;
    requestDurations[key] = { count: 0, totalMs: 0, maxMs: 0, p99: [] };
  }
  const entry = requestDurations[key]!;
  entry.count++;
  entry.totalMs += durationMs;
  if (durationMs > entry.maxMs) entry.maxMs = durationMs;
  // Keep last 100 durations for p99 approximation
  entry.p99.push(durationMs);
  if (entry.p99.length > 100) entry.p99.shift();
}

function getSnapshot(): MetricsSnapshot {
  const uptimeMs = Date.now() - metrics.startedAt;
  const endpoints: MetricsSnapshot['endpoints'] = {};
  for (const [key, val] of Object.entries(requestDurations)) {
    const sorted = [...val.p99].sort((a, b) => a - b);
    endpoints[key] = {
      count: val.count,
      avgMs: val.count > 0 ? Math.round(val.totalMs / val.count) : 0,
      maxMs: val.maxMs,
      p99Ms: sorted.length > 0 ? sorted[Math.floor(sorted.length * 0.99)]! : 0,
    };
  }
  return {
    ...metrics,
    uptimeMs,
    uptimeSec: Math.floor(uptimeMs / 1000),
    endpoints,
  };
}

export { metrics, incr, trackRequestDuration, getSnapshot, DB_SLOW_THRESHOLD_MS };
