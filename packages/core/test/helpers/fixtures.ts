// Fixtures the core suites share, so the copies cannot drift apart.

/** A 32-byte value with every byte set to `byte`. */
export const filled = (byte: number): Uint8Array => new Uint8Array(32).fill(byte);
