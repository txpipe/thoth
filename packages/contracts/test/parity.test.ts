// Parity between the off-chain encoders in `@txpipe/thoth-core/claim`
// (`claimToMessage`, `nullifierOf`, `toContractClaim`) and the contract's own
// `buildMessage` and `nullifierOf` (`pureCircuits.message`, `pureCircuits.nullifierOf`),
// over seeded random claims for the numeric, bytes and layout mocks. A failure
// names its seed: rerun with `THOTH_SEED=<seed>` to replay it.
//
// The end-to-end check signs `claimToMessage`'s output and submits it to the
// simulator: the contract re-derives the message in-circuit, so it accepts only
// if the off-chain encoder matches the contract's own.
import {
  type ContractClaim,
  claimToMessage,
  nullifierOf,
  toContractClaim,
} from '@txpipe/thoth-core/claim';
import { describe, expect, it } from 'vitest';
import { pureCircuits } from '../artifacts/mock_attestation/contract/index.js';
import { pureCircuits as bytesPureCircuits } from '../artifacts/mock_attestation_bytes/contract/index.js';
import { pureCircuits as layoutPureCircuits } from '../artifacts/mock_attestation_layout/contract/index.js';
import {
  DEFAULT_HOLDER_SECRET,
  DUMMY_SIGNATURE,
  makeClaim,
  makeNotaryKey,
} from './helpers/fixtures.js';
import { createPrivateState } from './helpers/private-state.js';
import { RUNS, randomClaim, SEED, SeededRandom } from './helpers/random-claims.js';
import { signMessage } from './helpers/sign.js';
import { MockAttestationSim } from './helpers/sim.js';

const notaryKeys = [makeNotaryKey(), makeNotaryKey(), makeNotaryKey()] as const;
const registryKeys = notaryKeys.map((k) => k.pk);
const holder = DEFAULT_HOLDER_SECRET;

type Circuits = {
  message: (claim: ContractClaim) => bigint[];
  nullifierOf: (claim: ContractClaim) => Uint8Array;
};

// Each mock's layout (V numeric slots, W byte slots) and its compiled circuits.
const mocks: { name: string; v: number; w: number; circuits: Circuits }[] = [
  { name: 'numeric mock (V = 3, W = 0)', v: 3, w: 0, circuits: pureCircuits },
  { name: 'bytes mock (V = 3, W = 1)', v: 3, w: 1, circuits: bytesPureCircuits },
  { name: 'layout mock (V = 0, W = 3)', v: 0, w: 3, circuits: layoutPureCircuits },
];

describe.each(mocks)(`off-chain parity over random claims, $name (seed ${SEED})`, (mock) => {
  // Every property draws its own claims from the seed, so each replays alone.
  const claims = () => {
    const rng = new SeededRandom(SEED);
    return Array.from({ length: RUNS }, () => randomClaim(rng, mock.v, mock.w));
  };

  it('nullifierOf equals the circuit nullifier', () => {
    claims().forEach((claim, run) => {
      expect(nullifierOf(claim), `run ${run}`).toEqual(
        mock.circuits.nullifierOf(toContractClaim(claim)),
      );
    });
  });

  it('claimToMessage equals the circuit message', () => {
    claims().forEach((claim, run) => {
      expect(claimToMessage(claim), `run ${run}`).toEqual(
        mock.circuits.message(toContractClaim(claim)),
      );
    });
  });
});

describe('claimToMessage end to end', () => {
  it('accepts signatures made over claimToMessage output', async () => {
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
      holderSecret: holder,
    });

    // The vault key is the off-chain nullifier, so a holder can find its entry.
    expect(sim.ledgerView().A_claimsVault.member(nullifierOf({ ...claim, byteValues: [] }))).toBe(
      true,
    );
  });
});
