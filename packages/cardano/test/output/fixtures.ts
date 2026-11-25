// Fixed cardano@1 values shared by the kind's tests.

import {
  deriveCardanoClaim,
  type OutputLocator,
  type OutputObservation,
  type OutputPolicy,
} from '@txpipe/thoth-cardano';
import type { Claim } from '@txpipe/thoth-core/claim';
import { filled } from '@txpipe/thoth-test-utils/bytes';
import {
  CARDANO_BLOCK_HASH,
  CARDANO_TEST_ADDRESS,
  CARDANO_TX_HASH,
} from '@txpipe/thoth-test-utils/cardano-fixtures';

/** A preview payment address at the smallest CIP-19 length; the checksum is a fixture. */
export const TEST_ADDRESS = CARDANO_TEST_ADDRESS;

/** The canonical output policy: preview, depth 3, five numeric facts and one byte fact. */
export const POLICY: OutputPolicy = {
  kind: 'output',
  network: 'preview',
  networkMagic: 2,
  confirmationDepth: 3,
  address: TEST_ADDRESS,
  slots: [
    { slot: 0, name: 'blockTime' },
    { slot: 1, name: 'slot' },
    { slot: 2, name: 'blockNumber' },
    { slot: 3, name: 'lovelace' },
    { slot: 4, name: 'outputIndex' },
    { slot: 5, name: 'txHash' },
  ],
};

/** The event's transaction hash. */
export const TX_HASH = CARDANO_TX_HASH;

/** The block hash the event landed in. */
export const BLOCK_HASH = CARDANO_BLOCK_HASH;

/** The client's evidence: the locator only. */
export const LOCATOR: OutputLocator = { txHash: TX_HASH, outputIndex: 1 };

/** The event as an attestor reads it, with the tip exactly at the policy depth. */
export const OBSERVATION: OutputObservation = {
  networkMagic: 2,
  tipBlockNumber: 1003,
  block: { hash: BLOCK_HASH, slot: 123_456, blockNumber: 1000, time: 1_700_000_000 },
  output: {
    txHash: TX_HASH,
    outputIndex: 1,
    address: TEST_ADDRESS,
    lovelace: 5_000_000n,
    assets: [],
  },
};

/** The pinned native asset: policy id 28 bytes, name 4 bytes, both lowercase hex. */
export const ASSET_PIN = { policyId: 'ab'.repeat(28), assetName: 'cd'.repeat(4) };

/** The output policy with the asset pinned and its quantity measured at slot 3. */
export const ASSET_POLICY: OutputPolicy = {
  ...POLICY,
  asset: ASSET_PIN,
  slots: [
    { slot: 0, name: 'blockTime' },
    { slot: 1, name: 'slot' },
    { slot: 2, name: 'blockNumber' },
    { slot: 3, name: 'assetQuantity' },
    { slot: 4, name: 'outputIndex' },
    { slot: 5, name: 'txHash' },
  ],
};

/** The event with the pinned asset present. */
export const ASSET_OBSERVATION: OutputObservation = {
  ...OBSERVATION,
  output: { ...OBSERVATION.output, assets: [{ ...ASSET_PIN, quantity: 700n }] },
};

/** The output policy whose byte slots carry the watched address and the block. */
export const BYTE_FACT_POLICY: OutputPolicy = {
  ...POLICY,
  slots: [
    { slot: 0, name: 'blockTime' },
    { slot: 1, name: 'slot' },
    { slot: 2, name: 'blockNumber' },
    { slot: 3, name: 'lovelace' },
    { slot: 4, name: 'outputIndex' },
    { slot: 5, name: 'addressHash' },
    { slot: 6, name: 'blockHash' },
  ],
};

/** A fixed app id, 32 bytes. */
export const APP_ID = filled(0xaa);

/** A fixed holder commitment, 32 bytes. */
export const HOLDER = filled(0xbb);

/** Derive a claim from `observation` under the fixture defaults. */
export const claimFor = (
  observation: OutputObservation = OBSERVATION,
  options: { policy?: OutputPolicy; valueSlots?: number; byteSlots?: number } = {},
): Claim<number, number> =>
  deriveCardanoClaim({
    policy: options.policy ?? POLICY,
    observation,
    appId: APP_ID,
    holder: HOLDER,
    valueSlots: options.valueSlots ?? 5,
    byteSlots: options.byteSlots ?? 1,
  });
