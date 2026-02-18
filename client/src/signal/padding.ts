// Message padding to resist traffic analysis via ciphertext length.
// Uses power-of-2 bucket sizing with zero-fill (Degabriele et al. CCS 2021).

const PADDING_VERSION = 0x01;
const HEADER_SIZE = 5; // 1 byte version + 4 bytes big-endian length
const MIN_BUCKET = 256;
const MAX_BUCKET = 32768; // 32 KB

function nextPowerOf2(n: number): number {
  if (n <= MIN_BUCKET) return MIN_BUCKET;
  if (n >= MAX_BUCKET) return MAX_BUCKET;
  // Bit trick: round up to next power of 2
  let v = n - 1;
  v |= v >> 1;
  v |= v >> 2;
  v |= v >> 4;
  v |= v >> 8;
  v |= v >> 16;
  return v + 1;
}

export function pad(plaintext: Uint8Array): Uint8Array {
  const totalNeeded = HEADER_SIZE + plaintext.length;
  const bucketSize = nextPowerOf2(totalNeeded);
  const padded = new Uint8Array(bucketSize); // zero-filled by default

  // Header: version (1 byte) + original length (4 bytes big-endian)
  padded[0] = PADDING_VERSION;
  padded[1] = (plaintext.length >> 24) & 0xff;
  padded[2] = (plaintext.length >> 16) & 0xff;
  padded[3] = (plaintext.length >> 8) & 0xff;
  padded[4] = plaintext.length & 0xff;

  // Copy plaintext after header
  padded.set(plaintext, HEADER_SIZE);

  // Remaining bytes are already zero (Uint8Array default)
  return padded;
}

export function unpad(padded: Uint8Array): Uint8Array {
  // IMP-4 fix: single opaque error for all validation failures to prevent
  // information leakage about padding structure via distinct error paths.
  if (padded.length < HEADER_SIZE) {
    throw new Error('Decryption failed');
  }

  const version = padded[0];
  if (version !== PADDING_VERSION) {
    throw new Error('Decryption failed');
  }

  const originalLength =
    (padded[1]! << 24) |
    (padded[2]! << 16) |
    (padded[3]! << 8) |
    padded[4]!;

  if (originalLength < 0 || HEADER_SIZE + originalLength > padded.length) {
    throw new Error('Decryption failed');
  }

  return padded.slice(HEADER_SIZE, HEADER_SIZE + originalLength);
}
