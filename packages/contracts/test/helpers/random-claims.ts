// Seeded random claims for the parity tests. Set THOTH_SEED to replay a run;
// a failing test names the seed it ran with.
import { createHash, randomInt } from 'node:crypto';
import type { Claim } from '@txpipe/thoth-core/claim';

/** The seed this run draws claims from: `THOTH_SEED`, or a fresh one. */
export const SEED: number = process.env.THOTH_SEED
  ? Number.parseInt(process.env.THOTH_SEED, 10)
  : randomInt(2 ** 31);

/**
 * A deterministic byte stream: SHA-256 of the seed and a counter, so the same
 * seed draws the same claims on every machine.
 */
export class SeededRandom {
  private counter = 0;
  private pool = new Uint8Array(0);
  private seed: number;

  constructor(seed: number) {
    this.seed = seed;
  }

  /** `length` bytes from the stream. */
  bytes(length: number): Uint8Array {
    while (this.pool.length < length) {
      const block = createHash('sha256')
        .update(`${this.seed}:${this.counter++}`)
        .digest();
      const next = new Uint8Array(this.pool.length + block.length);
      next.set(this.pool);
      next.set(block, this.pool.length);
      this.pool = next;
    }
    const out = this.pool.slice(0, length);
    this.pool = this.pool.slice(length);
    return out;
  }

  /** An integer in `[0, 2^bits)`. */
  uint(bits: number): bigint {
    const raw = this.bytes(Math.ceil(bits / 8)).reduce(
      (acc, byte, i) => acc + (BigInt(byte) << BigInt(8 * i)),
      0n,
    );
    return raw & ((1n << BigInt(bits)) - 1n);
  }

  boolean(): boolean {
    return (this.bytes(1)[0] ?? 0) % 2 === 1;
  }

  /**
   * An integer in `[0, 2^bits)` that is an edge value (0, 1, the maximum) half
   * the time, so the bounds of each width are drawn often.
   */
  edgyUint(bits: number): bigint {
    const max = (1n << BigInt(bits)) - 1n;
    switch (this.uint(3)) {
      case 0n:
        return 0n;
      case 1n:
        return 1n;
      case 2n:
        return max;
      case 3n:
        return max - 1n;
      default:
        return this.uint(bits);
    }
  }

  /** 32 bytes, all zero, all 0xff or random. */
  bytes32(): Uint8Array {
    switch (this.uint(3)) {
      case 0n:
        return new Uint8Array(32);
      case 1n:
        return new Uint8Array(32).fill(0xff);
      default:
        return this.bytes(32);
    }
  }
}

/**
 * A random claim with `v` numeric and `w` byte slots that obeys the absent-slot
 * law (an absent slot carries zero), with any version, windows and 32-byte
 * fields.
 */
export const randomClaim = <V extends number, W extends number>(
  rng: SeededRandom,
  v: V,
  w: W,
): Claim<V, W> => {
  const present = Array.from({ length: v + w }, () => rng.boolean());
  return {
    version: rng.edgyUint(8),
    appId: rng.bytes32(),
    policyHash: rng.bytes32(),
    windowStart: rng.edgyUint(32),
    windowEnd: rng.edgyUint(32),
    subjectHash: rng.bytes32(),
    holder: rng.bytes32(),
    salt: rng.bytes32(),
    present,
    values: Array.from({ length: v }, (_, i) => (present[i] ? rng.edgyUint(64) : 0n)),
    byteValues: Array.from({ length: w }, (_, i) =>
      present[v + i] ? rng.bytes32() : new Uint8Array(32),
    ),
  };
};

/** How many random claims each parity property draws. */
export const RUNS = 200;
