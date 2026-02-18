// Key transparency gossip: detect split-view attacks by comparing
// key log hashes seen by different parties.
//
// When Alice fetches Bob's bundle, she stores Bob's keyLogProof hash.
// When Bob sends a message, he includes his own latest key log hash.
// Alice compares Bob's claimed hash with what she saw from the server.
// A mismatch indicates the server may be presenting different views.

import { STORES, get, put } from '../storage/indexeddb';
import { api } from '../api';
import { verifyKeyLogEntry } from './sealed';

interface StoredKeyLogProof {
  sequence: number;
  entryHash: string;
  fetchedAt: number;
}

/**
 * Store a key log proof seen in a bundle response.
 */
export async function storeKeyLogProof(userId: number, proof: { sequence: number; entryHash: string }): Promise<void> {
  await put(STORES.META, `keylog:${userId}`, {
    sequence: proof.sequence,
    entryHash: proof.entryHash,
    fetchedAt: Date.now(),
  });
}

/**
 * Get the last-seen key log proof for a user.
 */
export async function getStoredKeyLogProof(userId: number): Promise<StoredKeyLogProof | null> {
  return (await get(STORES.META, `keylog:${userId}`)) as StoredKeyLogProof | null;
}

/**
 * Get our own latest key log hash (for sending as gossip).
 */
let ownKeyLogHash: string | null = null;

export function setOwnKeyLogHash(_userId: number, hash: string): void {
  ownKeyLogHash = hash;
}

export function getOwnKeyLogHash(): string | null {
  return ownKeyLogHash;
}

/**
 * Verify a gossip hash from a sender against what we've seen.
 * Returns true if consistent (or no data to compare), false if mismatch.
 */
export async function verifyGossipHash(senderUserId: number, claimedHash: string): Promise<{ consistent: boolean; details?: string }> {
  const stored = await getStoredKeyLogProof(senderUserId);
  if (!stored) {
    // No prior data — nothing to compare against
    return { consistent: true };
  }

  if (stored.entryHash === claimedHash) {
    return { consistent: true };
  }

  // Mismatch! The sender's key log hash differs from what we saw.
  // This could mean:
  // 1. The sender uploaded a new key since we fetched their bundle (benign)
  // 2. The server is presenting different views (attack)
  // To distinguish, fetch the sender's current key log from the server.
  try {
    const log = await api.getKeyLog(senderUserId);
    if (log.length > 0) {
      const latest = log[log.length - 1]!;

      // CRIT-2: Verify Ed25519 signature before trusting server-provided entry
      const sigValid = await verifyKeyLogEntry(latest);
      if (!sigValid) {
        return {
          consistent: false,
          details: `Key log entry for user ${senderUserId} has invalid signature — server may be forging entries`,
        };
      }

      if (latest.entryHash === claimedHash) {
        // Claimed hash matches the server's current view — sender just updated their key
        await storeKeyLogProof(senderUserId, { sequence: latest.sequence, entryHash: latest.entryHash });
        return { consistent: true };
      }
    }
  } catch {
    // CRIT-3 fix: network failure during verification is indeterminate, not consistent.
    // A state-level adversary could cause this failure to suppress the alert.
    return {
      consistent: false,
      details: `Key log verification inconclusive for user ${senderUserId}: network error during cross-check. Hash mismatch detected but could not resolve.`,
    };
  }

  return {
    consistent: false,
    details: `Key log hash mismatch for user ${senderUserId}: expected ${stored.entryHash.slice(0, 16)}..., got ${claimedHash.slice(0, 16)}...`,
  };
}

export function clearKeyLogGossip(): void {
  ownKeyLogHash = null;
}
