import { describe, expect, it } from 'vitest';
import { decode, encode } from '../src/cipher.js';

describe('cipher', () => {
  it('round-trips arbitrary data', () => {
    for (const len of [0, 1, 15, 32, 64, 257, 1024]) {
      const buf = Buffer.alloc(len);
      for (let i = 0; i < len; i++) buf[i] = (i * 31 + 7) & 0xff;
      expect(decode(encode(buf)).equals(buf)).toBe(true);
    }
  });

  it('does not mutate input', () => {
    const input = Buffer.from([1, 2, 3, 4, 5]);
    const copy = Buffer.from(input);
    encode(input);
    expect(input.equals(copy)).toBe(true);
  });

  it('is stable across multiple calls (no shared state)', () => {
    const data = Buffer.from('hello world');
    const a = encode(data);
    const b = encode(data);
    expect(a.equals(b)).toBe(true);
  });

  it('encode and decode are the same function', () => {
    expect(decode).toBe(encode);
  });
});
