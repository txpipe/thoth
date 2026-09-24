// Parity between the off-chain message encoder (`@thoth/core/claim`'s
// `claimToMessage`) and the contract's own `buildMessage` (`pureCircuits.message`).
//
// Level 1 asserts the encoders are field-for-field identical across a spread of
// claims. Level 2 signs over `claimToMessage`'s output and submits to the
// simulator: the contract ignores the submitted message and re-derives
// `buildMessage(claim)` in-circuit, so acceptance is only possible if the
// off-chain encoder is byte-identical to the contract's own.
//
// The encoding vectors (`packages/core/test/claim-vectors.json`) pin known
// claims to their expected field vectors; both encoders must reproduce them.
import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { claimToMessage } from '@thoth/core/claim';
import { describe, expect, it } from 'vitest';
import { type A_Claim, pureCircuits } from '../artifacts/mock_attestation/contract/index.js';
import {
  DUMMY_SIGNATURE,
  idOf,
  makeClaim,
  makeNotaryKey,
  TEST_HOLDER_SECRET,
} from './helpers/fixtures.js';
import { createPrivateState } from './helpers/private-state.js';
import { signMessage } from './helpers/sign.js';
import { MockAttestationSim } from './helpers/sim.js';

const notaryKeys = [makeNotaryKey(), makeNotaryKey(), makeNotaryKey()] as const;
const registryKeys = notaryKeys.map((k) => k.pk);
const holderSecret = TEST_HOLDER_SECRET;

// A signature that can never verify against a non-empty registry slot.

type Vector = {
  name: string;
  claim: Record<'version' | 'kind' | 'windowStart' | 'windowEnd', string> &
    Record<'policyDigest' | 'requestBinding' | 'holder' | 'nonce', string> & {
      present: boolean[];
      values: string[];
    };
  message: string[];
};

const vectors = JSON.parse(
  readFileSync(new URL('../../core/test/claim-vectors.json', import.meta.url), 'utf-8'),
) as Vector[];

const bytes = (hex: string): Uint8Array => new Uint8Array(Buffer.from(hex, 'hex'));

const claimOf = ({ claim }: Vector): A_Claim => ({
  version: BigInt(claim.version),
  kind: BigInt(claim.kind),
  policyDigest: bytes(claim.policyDigest),
  requestBinding: bytes(claim.requestBinding),
  holder: bytes(claim.holder),
  nonce: bytes(claim.nonce),
  windowStart: BigInt(claim.windowStart),
  windowEnd: BigInt(claim.windowEnd),
  present: claim.present,
  values: claim.values.map(BigInt),
});

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

  describe('encoding vectors', () => {
    it.each(vectors)('$name', (vector) => {
      const expected = vector.message.map(BigInt);
      expect(claimToMessage(claimOf(vector))).toEqual(expected);
      expect(pureCircuits.message(claimOf(vector))).toEqual(expected);
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

      const sim = new MockAttestationSim(createPrivateState(holderSecret), registryKeys);
      sim.call('verifyAttestation', {
        claim,
        signatures,
        commitRand,
        holderSecret,
      });

      expect(sim.ledgerView().A_claimsVault.member(idOf(claim, commitRand))).toBe(true);
    });
  });
});
