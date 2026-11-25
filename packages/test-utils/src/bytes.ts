// Shared byte and encoding primitives for Thoth workspace tests.
import { createHash } from 'node:crypto';

/** Build a byte array of `length` (default 32) filled with `byte`. */
export const filled = (byte: number, length = 32): Uint8Array => new Uint8Array(length).fill(byte);

/** Encode `bytes` as lowercase hex without a `0x` prefix. */
export const hex = (bytes: Uint8Array): string => Buffer.from(bytes).toString('hex');

/** Compute the lowercase-hex SHA-256 digest of a UTF-8 string. */
export const sha256 = (text: string): string =>
  createHash('sha256').update(text, 'utf-8').digest('hex');

/**
 * Build a 32-byte array `[0, 1, ..., 31]` whose bytes differ across the
 * 16-byte half boundary, so swapped or reversed halves fail assertions.
 */
export const fullSpan = (): Uint8Array => Uint8Array.from({ length: 32 }, (_, i) => i);

/**
 * Decode `bytes` as an unsigned little-endian integer (first byte least
 * significant), matching Compact's `convertBytesToUint`.
 */
export const le = (bytes: Uint8Array): bigint =>
  bytes.reduce((acc, byte, i) => acc + BigInt(byte) * 256n ** BigInt(i), 0n);

/**
 * Zero-pad a UTF-8 string or raw byte array to 32 bytes.
 *
 * @throws if the encoded bytes exceed 32 bytes.
 */
export const padded32 = (value: string | Uint8Array): Uint8Array => {
  const bytes = typeof value === 'string' ? new TextEncoder().encode(value) : value;
  if (bytes.length > 32) {
    throw new Error(`padded32: value is ${bytes.length} bytes, over the 32-byte limit`);
  }
  const padded = new Uint8Array(32);
  padded.set(bytes);
  return padded;
};
