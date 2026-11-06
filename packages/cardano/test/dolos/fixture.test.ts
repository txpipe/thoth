// Recorded preview fixture: one Dolos UTxO-RPC read through
// https://cardano-preview.utxorpc-m1.demeter.run for tx
// 65d12c1a…76fdfe8f, output 0, at
// addr_test1qpsuxemj2fmw6h3w42cdmc6cpu0fz68p9clyudx6p68xa3qxnsdv46lhvyng372rnslvuaw80gnqd3tru8yet2mgakxsf9yv63.
// The block is 4,825,241 (slot 127,168,698, hash 04198a46…c5787fd); the tip
// was 4,825,280 when recorded. The endpoint key is not stored here.

import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { cardano, query } from '@utxorpc/spec';
import { describe, expect, it } from 'vitest';
import { type DolosSource, readRawEvent } from '../../src/dolos/index.js';

const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), 'fixtures');

const TX_HASH = '65d12c1a8204919d850739e9edac795dd69afcf09fd6d77d85c1ffae76fdfe8f';
const ADDRESS =
  'addr_test1qpsuxemj2fmw6h3w42cdmc6cpu0fz68p9clyudx6p68xa3qxnsdv46lhvyng372rnslvuaw80gnqd3tru8yet2mgakxsf9yv63';

const readFixture = (name: string): string => readFileSync(join(FIXTURES, name), 'utf8');

const response = query.ReadTxResponse.fromJsonString(readFixture('read-tx.json'));
const genesis = cardano.Genesis.fromJsonString(readFixture('read-genesis.json'));
const tipBlock = cardano.Block.fromJsonString(readFixture('fetch-block-tip.json'));
const tipRef = response.ledgerTip;
if (!tipRef) {
  throw new Error('recorded fixture has no ledger tip');
}

const source: DolosSource = {
  readTx: async () => response,
  readGenesis: async () => genesis,
  readTip: async () => ({ slot: tipRef.slot, hash: tipRef.hash }),
  fetchBlock: async () => tipBlock,
};

describe('recorded Dolos fixture', () => {
  it('reads the recorded preview output and block as raw fields', async () => {
    const event = await readRawEvent({ source, txHash: TX_HASH, outputIndex: 0 });

    expect(event).toEqual({
      networkMagic: 2,
      tipBlockNumber: 4_825_280,
      block: {
        hash: '04198a461a26b6a5af06bb96d3b3e3730fe0210a93fb046481eb52f89c5787fd',
        slot: 127_168_698,
        blockNumber: 4_825_241,
        time: 1_793_824_698,
      },
      output: {
        txHash: TX_HASH,
        outputIndex: 0,
        address: ADDRESS,
        lovelace: 10_000_000_000n,
        assets: [],
      },
    });
  });
});
