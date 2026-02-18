import { describe, it, expect, vi, beforeEach } from 'vitest';
import crypto from 'crypto';

// Generate a test Ed25519 key pair for signing
const testKeyPair = crypto.generateKeyPairSync('ed25519');

// Mock dependencies before import
vi.mock('../../server/config', () => ({
  default: { IS_PRODUCTION: false },
}));
vi.mock('../../server/logger', () => ({
  default: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

// In-memory store for key log entries
let keyLogEntries: Array<{
  sequence: number;
  user_id: number;
  identity_key: string;
  previous_hash: string;
  entry_hash: string;
  signature: string;
  timestamp: string;
}> = [];
let nextSequence = 1;

vi.mock('../../server/db', () => ({
  db: {
    transaction: vi.fn((fn: (...args: unknown[]) => unknown) => fn),
  },
  stmt: {
    getLatestKeyLogEntry: {
      get: vi.fn(() => {
        if (keyLogEntries.length === 0) return undefined;
        const last = keyLogEntries[keyLogEntries.length - 1]!;
        return { sequence: last.sequence, entry_hash: last.entry_hash };
      }),
    },
    appendKeyLog: {
      run: vi.fn((userId: number, identityKey: string, previousHash: string, entryHash: string, signature: string) => {
        keyLogEntries.push({
          sequence: nextSequence++,
          user_id: userId,
          identity_key: identityKey,
          previous_hash: previousHash,
          entry_hash: entryHash,
          signature,
          timestamp: new Date().toISOString(),
        });
      }),
    },
    getKeyLogForUser: {
      all: vi.fn((userId: number) => keyLogEntries.filter(e => e.user_id === userId)),
    },
    getKeyLogRange: {
      all: vi.fn((afterSequence: number, limit: number) =>
        keyLogEntries.filter(e => e.sequence > afterSequence).slice(0, limit)),
    },
    getKeyLogLatestForUser: {
      get: vi.fn((userId: number) => {
        const userEntries = keyLogEntries.filter(e => e.user_id === userId);
        if (userEntries.length === 0) return undefined;
        return userEntries[userEntries.length - 1];
      }),
    },
  },
}));

vi.mock('../../server/senderCert', () => ({
  getSigningKey: vi.fn(() => testKeyPair.privateKey),
}));

import {
  appendToKeyLog,
  getKeyLogForUser,
  getKeyLogRange,
  getLatestKeyLogForUser,
  verifyChain,
} from '../../server/keyLog';

describe('keyLog', () => {
  beforeEach(() => {
    keyLogEntries = [];
    nextSequence = 1;
  });

  describe('appendToKeyLog', () => {
    it('creates first entry with genesis hash as previous', () => {
      const hash = appendToKeyLog(1, 'identityKey1');
      expect(typeof hash).toBe('string');
      expect(hash.length).toBe(64); // SHA-256 hex

      expect(keyLogEntries).toHaveLength(1);
      expect(keyLogEntries[0]!.previous_hash).toBe('0'.repeat(64));
      expect(keyLogEntries[0]!.user_id).toBe(1);
    });

    it('chains entries correctly', () => {
      const hash1 = appendToKeyLog(1, 'key1');
      const hash2 = appendToKeyLog(1, 'key2');

      expect(keyLogEntries).toHaveLength(2);
      expect(keyLogEntries[1]!.previous_hash).toBe(hash1);
      expect(hash2).not.toBe(hash1);
    });

    it('produces different hashes for different inputs', () => {
      const hash1 = appendToKeyLog(1, 'keyA');
      keyLogEntries = []; // reset to get fresh genesis
      nextSequence = 1;
      const hash2 = appendToKeyLog(2, 'keyA'); // different userId

      expect(hash1).not.toBe(hash2);
    });

    it('signs each entry with Ed25519', () => {
      appendToKeyLog(1, 'key1');
      const entry = keyLogEntries[0]!;
      // Verify the signature
      const valid = crypto.verify(
        null,
        Buffer.from(entry.entry_hash),
        testKeyPair.publicKey,
        Buffer.from(entry.signature, 'base64'),
      );
      expect(valid).toBe(true);
    });
  });

  describe('verifyChain', () => {
    it('returns true for an empty chain', () => {
      expect(verifyChain([])).toBe(true);
    });

    it('returns true for a valid single-entry chain', () => {
      appendToKeyLog(1, 'key1');
      expect(verifyChain(keyLogEntries)).toBe(true);
    });

    it('returns true for a valid multi-entry chain', () => {
      appendToKeyLog(1, 'key1');
      appendToKeyLog(2, 'key2');
      appendToKeyLog(1, 'key3');
      expect(verifyChain(keyLogEntries)).toBe(true);
    });

    it('detects a chain break (modified previous_hash)', () => {
      appendToKeyLog(1, 'key1');
      appendToKeyLog(2, 'key2');
      // Corrupt the chain
      keyLogEntries[1]!.previous_hash = 'a'.repeat(64);
      expect(verifyChain(keyLogEntries)).toBe(false);
    });

    it('detects a tampered entry hash', () => {
      appendToKeyLog(1, 'key1');
      // Modify the entry hash without updating the actual hash
      keyLogEntries[0]!.entry_hash = 'b'.repeat(64);
      expect(verifyChain(keyLogEntries)).toBe(false);
    });

    it('detects modified identity key (hash mismatch)', () => {
      appendToKeyLog(1, 'key1');
      keyLogEntries[0]!.identity_key = 'TAMPERED';
      expect(verifyChain(keyLogEntries)).toBe(false);
    });
  });

  describe('getKeyLogForUser', () => {
    it('returns only entries for the specified user', () => {
      appendToKeyLog(1, 'key1');
      appendToKeyLog(2, 'key2');
      appendToKeyLog(1, 'key3');

      const user1Log = getKeyLogForUser(1);
      expect(user1Log).toHaveLength(2);
      expect(user1Log.every(e => e.user_id === 1)).toBe(true);
    });
  });

  describe('getKeyLogRange', () => {
    it('returns entries after the given sequence', () => {
      appendToKeyLog(1, 'key1');
      appendToKeyLog(2, 'key2');
      appendToKeyLog(1, 'key3');

      const range = getKeyLogRange(1, 10);
      expect(range).toHaveLength(2);
      expect(range[0]!.sequence).toBe(2);
    });

    it('respects the limit parameter', () => {
      appendToKeyLog(1, 'key1');
      appendToKeyLog(2, 'key2');
      appendToKeyLog(1, 'key3');

      const range = getKeyLogRange(0, 2);
      expect(range).toHaveLength(2);
    });
  });

  describe('getLatestKeyLogForUser', () => {
    it('returns null if user has no entries', () => {
      expect(getLatestKeyLogForUser(999)).toBeNull();
    });

    it('returns the latest entry for a user', () => {
      appendToKeyLog(1, 'key1');
      appendToKeyLog(1, 'key2');

      const latest = getLatestKeyLogForUser(1);
      expect(latest).not.toBeNull();
      expect(latest!.entryHash).toBe(keyLogEntries[keyLogEntries.length - 1]!.entry_hash);
    });
  });
});
