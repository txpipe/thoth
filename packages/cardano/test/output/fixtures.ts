// Fixed cardano@1 values shared by the kind's tests.

import type { OutputLocator, OutputObservation, OutputPolicy } from '@thoth/cardano';

/** A preview payment address at the smallest CIP-19 length; the checksum is a fixture. */
export const TEST_ADDRESS = `addr_test1${'q'.repeat(53)}`;

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
export const TX_HASH = 'cd'.repeat(32);

/** The block hash the event landed in. */
export const BLOCK_HASH = 'ab'.repeat(32);

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
  },
};

/** A fixed app id, 32 bytes. */
export const APP_ID = new Uint8Array(32).fill(0xaa);

/** A fixed holder commitment, 32 bytes. */
export const HOLDER = new Uint8Array(32).fill(0xbb);
