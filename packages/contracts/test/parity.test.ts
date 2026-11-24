// Parity between the off-chain message encoder (`@thoth/core/claim`'s
// `claimToMessage`, and the `nullifierOf` it signs) and the contract's own
// `buildMessage` and `nullifierOf` (`pureCircuits.message`,
// `pureCircuits.nullifierOf`). `toContractClaim` is held to the same encoder:
// its witness shape must build the message `claimToMessage` signs.
//
// Level 1 asserts the encoders agree field for field across a spread of claims.
// Level 2 signs `claimToMessage`'s seven fields with the runtime's
// `jubjubSchnorrSign`, as an attestor does, and submits to the simulator. The
// contract ignores the submitted message: its registry absorbs
// `buildMessage(claim)`, a struct, into the Schnorr challenge, so acceptance is
// only possible if that challenge equals the signer's, bit for bit. Level 2 runs
// over random claims in both mocks, and checks that the client's
// `jubjubVerifier` vets each signature as the contract does.
import { randomBytes } from 'node:crypto';
import { jubjubVerifier } from '@thoth/client/jubjub';
import { claimToMessage, nullifierOf, toContractClaim } from '@thoth/core/claim';
import { describe, expect, it } from 'vitest';
import { type A_Claim, pureCircuits } from '../artifacts/mock_attestation/contract/index.js';
import type { B_Claim } from '../artifacts/mock_attestation_bytes/contract/index.js';
import {
  bySlot,
  DEFAULT_HOLDER_SECRET,
  idOf,
  makeClaim,
  makeNotaryKey,
  POLICY_B,
  randomByteClaim,
  randomClaim,
} from './helpers/fixtures.js';
import { createPrivateState } from './helpers/private-state.js';
import { coreOf, messageOf, signMessage } from './helpers/sign.js';
import { MockAttestationBytesSim, MockAttestationSim } from './helpers/sim.js';

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
  makeClaim({ values: [(1n << 64n) - 1n, 1n << 63n, 0n], present: [true, true, false] }),
  makeClaim({ appId: new Uint8Array(32).fill(0xa2), policyHash: POLICY_B }),
  makeClaim({ appId: new Uint8Array(32), policyHash: new Uint8Array(32).fill(0xff) }),
  makeClaim({ windowStart: 0n, windowEnd: 0n }),
  makeClaim({ windowStart: 1_800_000_000n, windowEnd: 0xffff_ffffn }),
];

// A 32-byte value's two message fields: byte 31, then bytes 0–30 read
// little-endian, as the `attestation.compact` header lists them.
const limbsOf = (bytes: Uint8Array): bigint[] => [
  BigInt(bytes[31] ?? 0),
  bytes.slice(0, 31).reduceRight((acc, byte) => (acc << 8n) | BigInt(byte), 0n),
];

describe('claimToMessage parity', () => {
  describe('field-for-field equality (level 1)', () => {
    it('matches the contract buildMessage for every claim shape', () => {
      for (const claim of claims) {
        const m = pureCircuits.message(claim);
        expect(claimToMessage(coreOf(claim))).toEqual([
          m.version,
          m.v,
          m.w,
          ...limbsOf(m.nullifier),
          ...limbsOf(m.holder),
        ]);
      }
    });

    it('matches the contract nullifierOf for every claim shape', () => {
      for (const claim of claims) {
        expect(nullifierOf(coreOf(claim))).toEqual(pureCircuits.nullifierOf(claim));
      }
    });

    it('converts a numeric-only core claim into the contract witness shape', () => {
      for (const claim of claims) {
        const core = { ...claim, byteValues: [] };
        const contractClaim = toContractClaim(core);
        expect(contractClaim).toEqual(claim);
        expect(nullifierOf(core)).toEqual(pureCircuits.nullifierOf(contractClaim));
      }
    });
  });

  describe('end-to-end accept (level 2)', () => {
    it('accepts signatures made over claimToMessage output', async () => {
      const claim = makeClaim({ values: [111n, 222n, 333n], present: [true, true, true] });
      const msg = claimToMessage({ ...claim, byteValues: [] });

      // Sign the off-chain encoder's message directly with the keys in slots 0 and 1.
      const signatures = bySlot([
        signMessage(notaryKeys[0].sk, msg).signature,
        signMessage(notaryKeys[1].sk, msg).signature,
        null,
      ]);

      const sim = await MockAttestationSim.create(createPrivateState(holder), registryKeys);
      await sim.call('verifyAttestation', {
        claim,
        signatures,
        holderSecret: holder,
      });

      expect(sim.ledgerView().A_claimsVault.member(idOf(claim))).toBe(true);
    });

    // Signs each claim as two attestors do, checks that the client vets the
    // signatures and refuses them for the claim under another salt, and submits.
    const acceptsRandomClaims = async (
      submit: (
        claim: A_Claim | B_Claim,
        secret: Uint8Array,
        sigs: ReturnType<typeof bySlot>,
      ) => Promise<unknown>,
      next: () => { claim: A_Claim | B_Claim; secret: Uint8Array },
    ) => {
      for (let i = 0; i < 32; i++) {
        const { claim, secret } = next();
        const message = messageOf(claim);
        const other = messageOf({ ...claim, salt: randomBytes(32) });
        const signed = [notaryKeys[0], notaryKeys[2]].map((key) => ({
          key,
          signature: signMessage(key.sk, message).signature,
        }));
        for (const { key, signature } of signed) {
          expect(jubjubVerifier.verify(key.pk, message, signature)).toBe(true);
          expect(jubjubVerifier.verify(key.pk, other, signature)).toBe(false);
        }
        const signatures = bySlot([
          signed[0]?.signature ?? null,
          null,
          signed[1]?.signature ?? null,
        ]);
        await submit(claim, secret, signatures);
      }
    };

    it('accepts runtime signatures over random numeric claims', async () => {
      const sim = await MockAttestationSim.create(createPrivateState(holder), registryKeys);
      await acceptsRandomClaims(async (claim, holderSecret, signatures) => {
        await sim.call('verifyAttestation', {
          claim: claim as A_Claim,
          signatures,
          holderSecret,
        });
        expect(sim.ledgerView().A_claimsVault.member(nullifierOf(coreOf(claim)))).toBe(true);
      }, randomClaim);
    });

    it('accepts runtime signatures over random byte-carrying claims', async () => {
      const sim = await MockAttestationBytesSim.create(
        createPrivateState<B_Claim>(holder),
        registryKeys,
      );
      await acceptsRandomClaims(async (claim, holderSecret, signatures) => {
        await sim.call('verifyAttestation', {
          claim: claim as B_Claim,
          signatures,
          holderSecret,
        });
        expect(sim.ledgerView().B_claimsVault.member(nullifierOf(coreOf(claim)))).toBe(true);
      }, randomByteClaim);
    });
  });
});
