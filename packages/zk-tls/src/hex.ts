// Byte/hex conversions shared by the kind's modules. Not exported by the package.

/** Lower hex of raw bytes, without an `0x` prefix. */
export const bytesToHex = (bytes: Uint8Array): string =>
  Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');

/** Decode `0x`-prefixed or bare hex into bytes. */
export const hexToBytes = (hex: string): Uint8Array =>
  new Uint8Array(Buffer.from(hex.replace(/^0x/, ''), 'hex'));
