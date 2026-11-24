// Parity between the off-chain message encoder (`@txpipe/thoth-core/claim`'s
// `claimToMessage`) and the contract's own `buildMessage` (`pureCircuits.message`).
// `toContractClaim` is held to the same encoder: its witness shape must build
// the message `claimToMessage` signs.
//
// Level 1 asserts the encoders are field-for-field identical across a spread of
// claims. Level 2 signs over `claimToMessage`'s output and submits to the
// simulator: the contract ignores the submitted message and re-derives
// `buildMessage(claim)` in-circuit, so acceptance is only possible if the
// off-chain encoder is byte-identical to the contract's own.
import { randomBytes } from 'node:crypto';
import { claimToMessage, toContractClaim } from '@txpipe/thoth-core/claim';
import { describe, expect, it } from 'vitest';
import { pureCircuits } from '../artifacts/mock_attestation/contract/index.js';
import {
  DEFAULT_HOLDER_SECRET,
  DUMMY_SIGNATURE,
  idOf,
  makeClaim,
  makeNotaryKey,
  POLICY_B,
} from './helpers/fixtures.js';
import { createPrivateState } from './helpers/private-state.js';
import { signMessage } from './helpers/sign.js';
import { MockAttestationSim } from './helpers/sim.js';

const notaryKeys = [makeNotaryKey(), makeNotaryKey(), makeNotaryKey()] as const;
const registryKeys = notaryKeys.map((k) => k.pk);
const holder = DEFAULT_HOLDER_SECRET;

const claims = [
  makeClaim(),
  makeClaim({ holder: new Uint8Array(32) }),
  makeClaim({ holder: Uint8Array.from({ length: 32 }, (_, i) => i) }),
  makeClaim({ holder: new Uint8Array(32).fill(0xff) }),
  makeClaim({ values: [100n, 200n, 300n], present: [true, true, true] }),
  makeClaim({ values: [0n, 0n, 0n], present: [true, false, false] }),
  makeClaim({ values: [0n, 200n, 0n], present: [false, true, false] }),
  makeClaim({ appId: new Uint8Array(32).fill(0xa2), policyHash: POLICY_B }),
  makeClaim({ appId: new Uint8Array(32), policyHash: new Uint8Array(32).fill(0xff) }),
  makeClaim({ windowStart: 0n, windowEnd: 0n }),
  makeClaim({ windowStart: 1_800_000_000n, windowEnd: 0xffff_ffffn }),
];

describe('claimToMessage parity', () => {
  describe('field-for-field equality (level 1)', () => {
    it('matches the contract buildMessage for every claim shape', () => {
      for (const claim of claims) {
        expect(claimToMessage({ ...claim, byteValues: [] })).toEqual(pureCircuits.message(claim));
      }
    });

    it('converts a numeric-only core claim into the contract witness shape', () => {
      for (const claim of claims) {
        const core = { ...claim, byteValues: [] };
        const contractClaim = toContractClaim(core);
        expect(contractClaim).toEqual(claim);
        expect(pureCircuits.message(contractClaim)).toEqual(claimToMessage(core));
      }
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
