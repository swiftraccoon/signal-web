import { hash as argon2Hash, verify as argon2Verify, Algorithm } from '@node-rs/argon2';
import bcrypt from 'bcrypt';

// RFC 9106 second recommendation: m=64MiB, t=3 iterations, p=4 parallelism
const ARGON2_OPTIONS = {
  memoryCost: 65536, // 64 MiB in KiB
  timeCost: 3,
  parallelism: 4,
  algorithm: Algorithm.Argon2id,
};

export async function hash(password: string): Promise<string> {
  return argon2Hash(password, ARGON2_OPTIONS);
}

export async function verify(password: string, storedHash: string): Promise<boolean> {
  if (isBcryptHash(storedHash)) {
    return bcrypt.compare(password, storedHash);
  }
  return argon2Verify(storedHash, password);
}

export function needsRehash(storedHash: string): boolean {
  return isBcryptHash(storedHash);
}

function isBcryptHash(h: string): boolean {
  return h.startsWith('$2b$') || h.startsWith('$2a$') || h.startsWith('$2y$');
}
