// The module parameters `thoth generate` derives from a policy's layout, the
// attestor list and the threshold.
import { describe, expect, it } from 'vitest';
import { moduleParameters } from '../src/parameters.js';

const layout = (valueSlots: number, byteSlots: number) => ({ valueSlots, byteSlots, names: [] });

describe('moduleParameters', () => {
  // Expected K values are the specializations the contract tests compile:
  // MockAttestation (V=3, B=0, K=20) and MockAttestationBytes (V=3, B=2, K=24).
  it('matches the numeric-only mock specialization', () => {
    expect(moduleParameters(layout(3, 0), 3, 2)).toEqual({ V: 3, W: 0, B: 0, K: 20, N: 2, M: 3 });
  });

  it('matches the byte-slot mock specialization, two halves per byte value', () => {
    expect(moduleParameters(layout(3, 1), 3, 2)).toEqual({ V: 3, W: 1, B: 2, K: 24, N: 2, M: 3 });
  });

  it('counts each byte value as two halves of the message', () => {
    expect(moduleParameters(layout(2, 2), 5, 3)).toEqual({ V: 2, W: 2, B: 4, K: 26, N: 3, M: 5 });
  });

  it.each([0, 4, 1.5])('refuses threshold %s for three attestors', (threshold) => {
    expect(() => moduleParameters(layout(1, 0), 3, threshold)).toThrow(
      `threshold must be an integer from 1 to 3, got ${threshold}`,
    );
  });

  it('refuses an empty attestor list', () => {
    expect(() => moduleParameters(layout(1, 0), 0, 1)).toThrow('at least one attestor');
  });

  it('refuses a layout with no slot', () => {
    expect(() => moduleParameters(layout(0, 0), 1, 1)).toThrow('the policy has no slot');
  });
});
