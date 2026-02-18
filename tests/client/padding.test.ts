import { describe, it, expect } from 'vitest';
import { pad, unpad } from '../../client/src/signal/padding';

describe('padding', () => {
  describe('pad', () => {
    it('pads a short message to minimum bucket size (256 bytes)', () => {
      const msg = new TextEncoder().encode('hello');
      const padded = pad(msg);
      expect(padded.length).toBe(256);
    });

    it('preserves the original message in the padded output', () => {
      const msg = new TextEncoder().encode('test message');
      const padded = pad(msg);
      // Version byte
      expect(padded[0]).toBe(0x01);
      // Length in big-endian
      expect(
        (padded[1]! << 24) | (padded[2]! << 16) | (padded[3]! << 8) | padded[4]!
      ).toBe(msg.length);
      // Original bytes after header
      const extracted = padded.slice(5, 5 + msg.length);
      expect(extracted).toEqual(msg);
    });

    it('fills remaining bytes with zeros', () => {
      const msg = new TextEncoder().encode('hi');
      const padded = pad(msg);
      // After header + message, rest should be zeros
      for (let i = 5 + msg.length; i < padded.length; i++) {
        expect(padded[i]).toBe(0);
      }
    });

    it('uses power-of-2 bucket sizes', () => {
      // Test various sizes: all output should be a power of 2
      const sizes = [1, 10, 100, 250, 300, 1000, 5000, 20000];
      for (const size of sizes) {
        const msg = new Uint8Array(size);
        const padded = pad(msg);
        // Check it's a power of 2
        expect(padded.length & (padded.length - 1)).toBe(0);
        // Should be at least 256
        expect(padded.length).toBeGreaterThanOrEqual(256);
      }
    });

    it('caps at 32KB max bucket', () => {
      // A 30KB message (+ 5 byte header = 30725, rounds to 32768)
      const msg = new Uint8Array(30720);
      const padded = pad(msg);
      expect(padded.length).toBe(32768);
    });

    it('handles empty input', () => {
      const msg = new Uint8Array(0);
      const padded = pad(msg);
      expect(padded.length).toBe(256); // min bucket
      expect(padded[0]).toBe(0x01);
      // Length should be 0
      expect((padded[1]! << 24) | (padded[2]! << 16) | (padded[3]! << 8) | padded[4]!).toBe(0);
    });
  });

  describe('unpad', () => {
    it('recovers the original message', () => {
      const original = new TextEncoder().encode('hello, world!');
      const padded = pad(original);
      const recovered = unpad(padded);
      expect(recovered).toEqual(original);
    });

    it('round-trips messages of various sizes', () => {
      const sizes = [0, 1, 5, 100, 251, 500, 1024, 8192, 30000];
      for (const size of sizes) {
        const original = new Uint8Array(size);
        crypto.getRandomValues(original);
        const padded = pad(original);
        const recovered = unpad(padded);
        expect(recovered).toEqual(original);
      }
    });

    it('throws on too-short input', () => {
      expect(() => unpad(new Uint8Array(4))).toThrow('Decryption failed');
      expect(() => unpad(new Uint8Array(0))).toThrow('Decryption failed');
    });

    it('throws on unknown version', () => {
      const padded = pad(new TextEncoder().encode('test'));
      padded[0] = 0x99; // corrupt version
      expect(() => unpad(padded)).toThrow('Decryption failed');
    });

    it('throws on invalid length (exceeds buffer)', () => {
      const padded = new Uint8Array(256);
      padded[0] = 0x01;
      // Set length to way more than available space
      padded[1] = 0xff;
      padded[2] = 0xff;
      padded[3] = 0xff;
      padded[4] = 0xff;
      expect(() => unpad(padded)).toThrow('Decryption failed');
    });

    it('throws on negative length (sign bit set)', () => {
      const padded = new Uint8Array(256);
      padded[0] = 0x01;
      // Set length such that top bit is set (negative in signed 32-bit)
      padded[1] = 0x80;
      padded[2] = 0x00;
      padded[3] = 0x00;
      padded[4] = 0x00;
      expect(() => unpad(padded)).toThrow('Decryption failed');
    });
  });

  describe('bucket boundaries', () => {
    it('message exactly at bucket boundary minus header stays in that bucket', () => {
      // 256 - 5 header = 251 bytes of content fits in 256 bucket
      const msg = new Uint8Array(251);
      const padded = pad(msg);
      expect(padded.length).toBe(256);
    });

    it('message one byte over boundary bumps to next bucket', () => {
      // 252 bytes + 5 header = 257, rounds up to 512
      const msg = new Uint8Array(252);
      const padded = pad(msg);
      expect(padded.length).toBe(512);
    });
  });
});
