// Key Transparency: append-only hash-chained identity key log.
// Each entry contains: userId, identityKey, previousHash, entryHash, signature.
// The server signs every entry with Ed25519 (same key as sender certificates).
// Clients audit the chain and gossip hashes to detect split-view attacks.

import crypto from 'crypto';
import { stmt } from './db';
import logger from './logger';

// Re-use the Ed25519 signing infrastructure from senderCert
// (importing the module triggers key initialization)
import { getSigningKey } from './senderCert';

interface KeyLogEntry {
  sequence: number;
  user_id: number;
  identity_key: string;
  previous_hash: string;
  entry_hash: string;
  signature: string;
  timestamp: string;
}

const GENESIS_HASH = '0'.repeat(64); // SHA-256 zero hash for the first entry

function computeEntryHash(userId: number, identityKey: string, previousHash: string): string {
  return crypto.createHash('sha256')
    .update(`${userId}:${identityKey}:${previousHash}`)
    .digest('hex');
}

function signEntry(entryHash: string): string {
  const signingKey = getSigningKey();
  const sig = crypto.sign(null, Buffer.from(entryHash), signingKey);
  return sig.toString('base64');
}

/**
 * Append a new entry to the key log when a user uploads/changes their identity key.
 * Returns the new entry's hash for inclusion in bundle responses.
 */
export function appendToKeyLog(userId: number, identityKey: string): string {
  // Get the latest entry's hash (or genesis hash if empty)
  const latest = stmt.getLatestKeyLogEntry.get() as { sequence: number; entry_hash: string } | undefined;
  const previousHash = latest?.entry_hash ?? GENESIS_HASH;

  const entryHash = computeEntryHash(userId, identityKey, previousHash);
  const signature = signEntry(entryHash);

  stmt.appendKeyLog.run(userId, identityKey, previousHash, entryHash, signature);
  logger.debug({ userId, entryHash, sequence: (latest?.sequence ?? 0) + 1 }, 'Key log entry appended');

  return entryHash;
}

/**
 * Get all key log entries for a specific user (for auditing their key history).
 */
export function getKeyLogForUser(userId: number): KeyLogEntry[] {
  return stmt.getKeyLogForUser.all(userId) as KeyLogEntry[];
}

/**
 * Get key log entries after a given sequence number (for sync/gossip).
 */
export function getKeyLogRange(afterSequence: number, limit: number): KeyLogEntry[] {
  return stmt.getKeyLogRange.all(afterSequence, limit) as KeyLogEntry[];
}

/**
 * Get the latest key log entry for a user (for inclusion in bundle responses).
 */
export function getLatestKeyLogForUser(userId: number): { sequence: number; entryHash: string; signature: string; timestamp: string } | null {
  const entry = stmt.getKeyLogLatestForUser.get(userId) as { sequence: number; entry_hash: string; signature: string; timestamp: string } | undefined;
  if (!entry) return null;
  return {
    sequence: entry.sequence,
    entryHash: entry.entry_hash,
    signature: entry.signature,
    timestamp: entry.timestamp,
  };
}

/**
 * Verify the integrity of the key log chain (for server-side auditing).
 */
export function verifyChain(entries: KeyLogEntry[]): boolean {
  let expectedPreviousHash = GENESIS_HASH;

  for (const entry of entries) {
    // Verify chain linkage
    if (entry.previous_hash !== expectedPreviousHash) {
      logger.error({ sequence: entry.sequence, expected: expectedPreviousHash, actual: entry.previous_hash }, 'Key log chain break detected');
      return false;
    }

    // Verify entry hash
    const computedHash = computeEntryHash(entry.user_id, entry.identity_key, entry.previous_hash);
    if (computedHash !== entry.entry_hash) {
      logger.error({ sequence: entry.sequence }, 'Key log entry hash mismatch');
      return false;
    }

    expectedPreviousHash = entry.entry_hash;
  }

  return true;
}
