// The signed message carries the layout. The observation identity is hashed as
// a plain concatenation, 136 + 9*V + 33*W bytes, so the layout mock (V = 0,
// W = 3) and a V = 11, W = 0 layout can serialize two claims to the same
// bytes and the same nullifier. Only the layout fields of the message tell
// them apart, and this test shows that is enough.
import { randomBytes } from 'node:crypto';
import { type Claim, claimToMessage, nullifierOf, toContractClaim } from '@txpipe/thoth-core/claim';
import { beforeEach, describe, expect, it } from 'vitest';
import type { L_Claim } from '../artifacts/mock_attestation_layout/contract/index.js';
import { pureCircuits } from '../artifacts/mock_attestation_layout/contract/index.js';
import {
  APP_ID,
  DEFAULT_HOLDER_SECRET,
  DUMMY_SIGNATURE,
  makeNotaryKey,
  nowSeconds,
  POLICY_A,
} from './helpers/fixtures.js';
import { createPrivateState } from './helpers/private-state.js';
import { signMessage } from './helpers/sign.js';
import { MockAttestationLayoutSim } from './helpers/sim.js';

const notaryKeys = [makeNotaryKey(), makeNotaryKey(), makeNotaryKey()] as const;
const registryKeys = notaryKeys.map((key) => key.pk);
const holder = DEFAULT_HOLDER_SECRET;

// The layout mock's claim as a core claim: three byte slots, all measured.
// After the common fields its identity is three values (96 bytes), then three
// flags of 1. The last value ends in eight bytes of 1, so the final 11 bytes
// are all 1.
const header = {
  version: 1n,
  appId: APP_ID,
  policyHash: POLICY_A,
  windowStart: nowSeconds() - 10n,
  windowEnd: nowSeconds(),
  subjectHash: randomBytes(32),
  holder: pureCircuits.holderCommitment(holder),
  salt: randomBytes(32),
};
const lastValue = new Uint8Array(32);
lastValue.set(randomBytes(24));
lastValue.fill(1, 24);
const byteValues = [randomBytes(32), randomBytes(32), lastValue];
const deployed: Claim<0, 3> = {
  ...header,
  present: Array<boolean>(3).fill(true),
  values: [],
  byteValues,
};

// The V = 11, W = 0 claim with the same identity bytes: the first 88 bytes of
// the byte values read as 11 little-endian `Uint<64>` values, then 11 flags
// of 1.
const valueBytes = Buffer.concat(byteValues).subarray(0, 88);
const competing: Claim<11, 0> = {
  ...header,
  present: Array<boolean>(11).fill(true),
  values: Array.from({ length: 11 }, (_, i) => valueBytes.readBigUInt64LE(8 * i)),
  byteValues: [],
};

const signedBy = (message: readonly bigint[]) => [
  signMessage(notaryKeys[0].sk, message).signature,
  signMessage(notaryKeys[1].sk, message).signature,
  DUMMY_SIGNATURE,
];

let sim: MockAttestationLayoutSim;

const submit = (signatures: ReturnType<typeof signedBy>) =>
  sim.call('verifyAttestation', {
    claim: toContractClaim(deployed),
    signatures,
    holderSecret: holder,
  });

describe('layout binding', () => {
  beforeEach(async () => {
    sim = await MockAttestationLayoutSim.create(createPrivateState<L_Claim>(holder), registryKeys);
  });

  it('builds two layouts whose claims share a nullifier', () => {
    const nullifier = pureCircuits.nullifierOf(toContractClaim(deployed));
    expect(nullifierOf(competing)).toEqual(nullifier);
    expect(nullifierOf(deployed)).toEqual(nullifier);
  });

  it('signs a message that differs only in the layout fields', () => {
    const own = pureCircuits.message(toContractClaim(deployed));
    const other = claimToMessage(competing);
    expect(own.slice(0, 3)).toEqual([1n, 0n, 3n]);
    expect(other.slice(0, 3)).toEqual([1n, 11n, 0n]);
    expect(other.slice(3)).toEqual(own.slice(3));
  });

  it('accepts signatures over its own layout', async () => {
    await submit(signedBy(claimToMessage(deployed)));
    expect(sim.ledgerView().L_claimsVault.size()).toBe(1n);
  });

  it('rejects signatures made for the other layout', async () => {
    await expect(submit(signedBy(claimToMessage(competing)))).rejects.toThrow(
      'Insufficient valid signatures',
    );
  });
});
