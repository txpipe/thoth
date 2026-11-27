import { slotSignaturesOf } from '@txpipe/thoth-client';
import { describe, expect, it } from 'vitest';

// Only the slot and the signature matter here; the rest of an attestation is opaque.
const collectedAt = (registryIndex: number, signature: string) => ({
  registryIndex,
  attestation: { claim: {}, message: [], publicKey: `pk-${signature}`, signature },
});

describe('slotSignaturesOf', () => {
  it('names each signature by its registry slot, in slot order', () => {
    expect(slotSignaturesOf([collectedAt(2, 'c'), collectedAt(0, 'a')])).toEqual([
      { registryIndex: 0n, signature: 'a' },
      { registryIndex: 2n, signature: 'c' },
    ]);
  });

  it('keeps one entry per collected attestation', () => {
    const collected = [collectedAt(4, 'e'), collectedAt(1, 'b'), collectedAt(3, 'd')];
    expect(slotSignaturesOf(collected).map((entry) => entry.signature)).toEqual(['b', 'd', 'e']);
  });

  it('rejects two attestations from one slot', () => {
    expect(() => slotSignaturesOf([collectedAt(1, 'a'), collectedAt(1, 'b')])).toThrow(RangeError);
  });

  it.each([-1, 65_536, 1.5, Number.NaN])('rejects the slot %s, which no registry has', (slot) => {
    expect(() => slotSignaturesOf([collectedAt(slot, 'a')])).toThrow(
      `registry slot ${slot} is not an integer in [0, 65535]`,
    );
  });

  it('accepts the highest slot a registry can have', () => {
    expect(slotSignaturesOf([collectedAt(65_535, 'a')])).toEqual([
      { registryIndex: 65_535n, signature: 'a' },
    ]);
  });
});
