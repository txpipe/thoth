// Byte/hex conversions shared by the kind's modules. Internal: not part of the
// package's public surface.

/**
 * Lowercase hex of raw bytes.
 *
 * @param bytes — the bytes to encode.
 * @returns the lower-hex string, without an `0x` prefix.
 */
export const bytesToHex = (bytes: Uint8Array): string =>
  Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');

/**
 * Decode a hex string into bytes.
 *
 * @param hex — `0x`-prefixed or bare hex.
 * @returns the decoded bytes.
 */
export const hexToBytes = (hex: string): Uint8Array =>
  new Uint8Array(Buffer.from(hex.replace(/^0x/, ''), 'hex'));
