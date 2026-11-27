// The signed message carries the layout. The observation identity is hashed as
// a plain concatenation, 136 + 9*V + 17*B bytes, so the layout mock (V = 0,
// B = 18) and a V = 34, B = 0 layout can serialize two claims to the same
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

// The layout mock's claim as a core claim: nine byte slots, all measured. After
// the common fields its identity is 18 halves (288 bytes), then 18 flags of 1.
// The last half is sixteen bytes of 1, so the final 34 bytes are all 1.
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
lastValue.set(randomBytes(16));
lastValue.fill(1, 16);
const byteValues = [...Array.from({ length: 8 }, () => randomBytes(32)), lastValue];
const deployed: Claim<0, 9> = {
  ...header,
  present: Array<boolean>(9).fill(true),
  values: [],
  byteValues,
};

// The V = 34, B = 0 claim with the same identity bytes: the first 272 bytes of
// halves read as 34 little-endian `Uint<64>` values, then 34 flags of 1.
const halfBytes = Buffer.concat(byteValues).subarray(0, 272);
const competing: Claim<34, 0> = {
  ...header,
  present: Array<boolean>(34).fill(true),
  values: Array.from({ length: 34 }, (_, i) => halfBytes.readBigUInt64LE(8 * i)),
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
    commitRand: randomBytes(32),
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
    expect(own.slice(0, 3)).toEqual([1n, 0n, 18n]);
    expect(other.slice(0, 3)).toEqual([1n, 34n, 0n]);
    expect(other.slice(3)).toEqual(own.slice(3));
  });

  it('accepts signatures over its own layout', async () => {
    await submit(signedBy(claimToMessage(deployed)));
    expect(sim.ledgerView().L_nullifiers.size()).toBe(1n);
  });

  it('rejects signatures made for the other layout', async () => {
    await expect(submit(signedBy(claimToMessage(competing)))).rejects.toThrow(
      'Insufficient valid signatures',
    );
  });
});
