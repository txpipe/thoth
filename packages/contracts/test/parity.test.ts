// Parity between the off-chain message encoder (`@txpipe/thoth-core/claim`'s
// `claimToMessage`) and the contract's own `buildMessage` (`pureCircuits.message`).
// `toContractClaim` is held to the same encoder: its witness shape must build
// the message `claimToMessage` signs.
//
// Level 1 asserts the encoders are field-for-field identical over generated
// claims of each mock's shape. Level 2 signs over `claimToMessage`'s output and
// submits to the simulator: the contract ignores the submitted message and
// re-derives `buildMessage(claim)` in-circuit, so acceptance is only possible if
// the off-chain encoder is byte-identical to the contract's own.
import { randomBytes } from 'node:crypto';
import { claimToMessage, toContractClaim } from '@txpipe/thoth-core/claim';
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { anyClaim } from '../../core/test/arbitraries.js';
import { pureCircuits } from '../artifacts/mock_attestation/contract/index.js';
import { pureCircuits as bytesPureCircuits } from '../artifacts/mock_attestation_bytes/contract/index.js';
import {
  DEFAULT_HOLDER_SECRET,
  DUMMY_SIGNATURE,
  idOf,
  makeClaim,
  makeNotaryKey,
} from './helpers/fixtures.js';
import { createPrivateState } from './helpers/private-state.js';
import { signMessage } from './helpers/sign.js';
import { MockAttestationSim } from './helpers/sim.js';

const notaryKeys = [makeNotaryKey(), makeNotaryKey(), makeNotaryKey()] as const;
const registryKeys = notaryKeys.map((k) => k.pk);
const holder = DEFAULT_HOLDER_SECRET;

describe('claimToMessage parity', () => {
  describe('field-for-field equality (level 1)', () => {
    // Each circuit is specialized at one size, so each property generates
    // claims of its mock's shape: V = 3 numeric slots, plus W = 1 byte slot
    // (B = 2 halves) for the bytes mock.
    it('matches the numeric-only mock buildMessage (V = 3, K = 20)', () => {
      fc.assert(
        fc.property(anyClaim({ v: 3, w: 0 }), (claim) => {
          expect(pureCircuits.message(toContractClaim(claim))).toEqual(claimToMessage(claim));
        }),
      );
    });

    it('matches the bytes mock buildMessage (V = 3, B = 2, K = 24)', () => {
      fc.assert(
        fc.property(anyClaim({ v: 3, w: 1 }), (claim) => {
          expect(bytesPureCircuits.message(toContractClaim(claim))).toEqual(claimToMessage(claim));
        }),
      );
    });
  });

  describe('end-to-end accept (level 2)', () => {
    it('accepts signatures made over claimToMessage output', async () => {
      const commitRand = randomBytes(32);
      const claim = makeClaim({ values: [111n, 222n, 333n], present: [true, true, true] });
      const msg = claimToMessage({ ...claim, byteValues: [] });

      // Sign the off-chain encoder's message directly with the first two keys.
      const signatures = [
        signMessage(notaryKeys[0].sk, msg).signature,
        signMessage(notaryKeys[1].sk, msg).signature,
        DUMMY_SIGNATURE, // empty third slot — never verifies
      ];

      const sim = await MockAttestationSim.create(createPrivateState(holder), registryKeys);
      await sim.call('verifyAttestation', {
        claim,
        signatures,
        commitRand,
        holderSecret: holder,
      });

      expect(sim.ledgerView().A_claimsVault.member(idOf(claim, commitRand))).toBe(true);
    });
  });
});
