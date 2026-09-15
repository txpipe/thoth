// Parity between the off-chain message encoder (`@thoth/core/claim`'s
// `claimToMessage`) and the contract's own `buildMessage` (`pureCircuits.message`).
//
// Level 1 asserts the encoders are field-for-field identical across a spread of
// claims. Level 2 signs over `claimToMessage`'s output and submits to the
// simulator: the contract ignores the submitted message and re-derives
// `buildMessage(claim)` in-circuit, so acceptance is only possible if the
// off-chain encoder is byte-identical to the contract's own.
import { randomBytes } from 'node:crypto';
import { claimToMessage } from '@thoth/core/claim';
import { describe, expect, it } from 'vitest';
import { pureCircuits } from '../artifacts/mock_attestation/contract/index.js';
import { idOf, makeClaim, makeNotaryKey } from './helpers/fixtures.js';
import { createPrivateState } from './helpers/private-state.js';
import { signMessage } from './helpers/sign.js';
import { MockAttestationSim } from './helpers/sim.js';

const notaryKeys = [makeNotaryKey(), makeNotaryKey(), makeNotaryKey()] as const;
const registryKeys = notaryKeys.map((k) => k.pk);
const holder = randomBytes(32);

// A signature that can never verify against a non-empty registry slot.
const DUMMY_SIGNATURE = { announcement: { x: 0n, y: 1n }, response: 0n };

const claims = [
  makeClaim(),
  makeClaim({ values: [100n, 200n, 300n], present: [true, true, true] }),
  makeClaim({ values: [0n, 0n, 0n], present: [true, false, false] }),
  makeClaim({ values: [0n, 200n, 0n], present: [false, true, false] }),
];

describe('claimToMessage parity', () => {
  describe('field-for-field equality (level 1)', () => {
    it('matches the contract buildMessage for every claim shape', () => {
      for (const claim of claims) {
        expect(claimToMessage(claim)).toEqual(pureCircuits.message(claim));
      }
    });
  });

  describe('end-to-end accept (level 2)', () => {
    it('accepts signatures made over claimToMessage output', () => {
      const commitRand = randomBytes(32);
      const claim = makeClaim({ values: [111n, 222n, 333n], present: [true, true, true] });
      const msg = claimToMessage(claim);

      // Sign the off-chain encoder's message directly with the first two keys.
      const signatures = [
        signMessage(notaryKeys[0].sk, msg).signature,
        signMessage(notaryKeys[1].sk, msg).signature,
        DUMMY_SIGNATURE, // empty third slot — never verifies
      ];

      const sim = new MockAttestationSim(createPrivateState(holder), registryKeys);
      sim.call('verifyAttestation', {
        claim,
        signatures,
        commitRand,
        holderSecret: holder,
      });

      expect(sim.ledgerView().A_claimsVault.member(idOf(claim, commitRand))).toBe(true);
    });
  });
});
