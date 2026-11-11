// Unit tests for the raw Dolos UTxO-RPC source: one output read from synthetic
// protocol messages as the kind's observation, with one rejection per check.
// No network is used.

import { cardano, query } from '@utxorpc/spec';
import { describe, expect, it } from 'vitest';
import {
  bech32AddressOf,
  createDolosSource,
  type DolosSource,
  lovelaceOf,
  readRawEvent,
} from '../../src/dolos/index.js';

const BLOCK_HASH = 'ab'.repeat(32);
const TX_HASH = 'cd'.repeat(32);
const TIP_HASH = 'ef'.repeat(32);

// A CIP-19 base address: type 0 (key payment + key stake), testnet network id.
// The bytes are a fixture; the encoded form is the expected lowercase bech32.
const ADDRESS_BYTES = new Uint8Array(57);
const ADDRESS = `addr_test1${'q'.repeat(92)}0uk53y`;

const coin = (value: bigint): cardano.BigInt =>
  new cardano.BigInt({ bigInt: { case: 'int', value } });

const point = (overrides: Partial<query.ChainPoint> = {}): query.ChainPoint =>
  new query.ChainPoint({
    slot: 123_456n,
    hash: Uint8Array.from(Buffer.from(BLOCK_HASH, 'hex')),
    height: 1000n,
    timestamp: 1_700_000_000_000n,
    ...overrides,
  });

const output = (overrides: Partial<cardano.TxOutput> = {}): cardano.TxOutput =>
  new cardano.TxOutput({
    address: ADDRESS_BYTES,
    coin: coin(5_000_000n),
    ...overrides,
  });

const readTxResponse = (
  options: {
    outputs?: cardano.TxOutput[];
    successful?: boolean;
    blockRef?: query.ChainPoint;
    /** `null` omits the ledger tip, so the source's `readTip` is used. */
    ledgerTip?: query.ChainPoint | null;
    omitChain?: boolean;
  } = {},
): query.ReadTxResponse =>
  new query.ReadTxResponse({
    tx: new query.AnyChainTx({
      chain: options.omitChain
        ? undefined
        : {
            case: 'cardano',
            value: new cardano.Tx({
              outputs: options.outputs ?? [output()],
              successful: options.successful ?? true,
            }),
          },
      blockRef: options.blockRef ?? point(),
    }),
    ledgerTip: options.ledgerTip === null ? undefined : (options.ledgerTip ?? point()),
  });

const genesis = (networkMagic = 2): cardano.Genesis => new cardano.Genesis({ networkMagic });

const tipBlock = (height = 1003n): cardano.Block =>
  new cardano.Block({
    header: new cardano.BlockHeader({
      height,
      slot: 123_459n,
      hash: Uint8Array.from(Buffer.from(TIP_HASH, 'hex')),
    }),
    timestamp: 1_700_000_003_000n,
  });

const sourceWith = (
  options: {
    response?: query.ReadTxResponse;
    genesis?: cardano.Genesis;
    tip?: cardano.Block;
    tipPoint?: { slot: bigint; hash: Uint8Array };
  } = {},
): DolosSource => ({
  readTx: async () => options.response ?? readTxResponse(),
  readGenesis: async () => options.genesis ?? genesis(),
  readTip: async () =>
    options.tipPoint ?? {
      slot: 123_456n,
      hash: Uint8Array.from(Buffer.from(BLOCK_HASH, 'hex')),
    },
  fetchBlock: async () => options.tip ?? tipBlock(),
});

const read = (source: DolosSource = sourceWith(), outputIndex = 0) =>
  readRawEvent({ source, txHash: TX_HASH, outputIndex });

describe('readRawEvent', () => {
  it('reads one output and its block as raw fields', async () => {
    expect(await read()).toEqual({
      networkMagic: 2,
      tipBlockNumber: 1003,
      block: {
        hash: BLOCK_HASH,
        slot: 123_456,
        blockNumber: 1000,
        time: 1_700_000_000,
      },
      output: {
        txHash: TX_HASH,
        outputIndex: 0,
        address: ADDRESS,
        lovelace: 5_000_000n,
        assets: [],
      },
    });
  });

  it('decodes the output native assets', async () => {
    const withAssets = output({
      assets: [
        new cardano.Multiasset({
          policyId: Uint8Array.from({ length: 28 }, () => 0xab),
          assets: [
            new cardano.Asset({
              name: Uint8Array.from([0xcd, 0xef]),
              quantity: { case: 'outputCoin', value: coin(700n) },
            }),
          ],
        }),
      ],
    });
    const event = await read(sourceWith({ response: readTxResponse({ outputs: [withAssets] }) }));
    expect(event.output.assets).toEqual([
      { policyId: 'ab'.repeat(28), assetName: 'cdef', quantity: 700n },
    ]);
  });

  it('selects the output at the requested index', async () => {
    const response = readTxResponse({
      outputs: [output(), output({ coin: coin(7n) })],
    });
    const event = await read(sourceWith({ response }), 1);
    expect(event.output.outputIndex).toBe(1);
    expect(event.output.lovelace).toBe(7n);
  });

  it('falls back to readTip when the response has no ledger tip', async () => {
    const response = readTxResponse({ ledgerTip: null });
    const event = await read(sourceWith({ response }));
    expect(event.tipBlockNumber).toBe(1003);
  });

  it('rejects a transaction that is not successful', async () => {
    const response = readTxResponse({ successful: false });
    await expect(read(sourceWith({ response }))).rejects.toThrow('not successful');
  });

  it('rejects a transaction that is not Cardano', async () => {
    const response = readTxResponse({ omitChain: true });
    await expect(read(sourceWith({ response }))).rejects.toThrow('non-Cardano');
  });

  it('rejects a missing output', async () => {
    const response = readTxResponse({ outputs: [] });
    await expect(read(sourceWith({ response }))).rejects.toThrow('has no output 0');
  });

  it('rejects a missing block reference', async () => {
    const response = new query.ReadTxResponse({
      tx: new query.AnyChainTx({
        chain: {
          case: 'cardano',
          value: new cardano.Tx({ outputs: [output()], successful: true }),
        },
      }),
      ledgerTip: point(),
    });
    await expect(read(sourceWith({ response }))).rejects.toThrow('no block reference');
  });

  it('rejects a zero network magic', async () => {
    await expect(read(sourceWith({ genesis: genesis(0) }))).rejects.toThrow('network magic 0');
  });

  it('rejects a missing tip header', async () => {
    await expect(read(sourceWith({ tip: new cardano.Block({}) }))).rejects.toThrow('no header');
  });

  it('rejects a missing block time', async () => {
    const response = readTxResponse({ blockRef: point({ timestamp: 0n }) });
    await expect(read(sourceWith({ response }))).rejects.toThrow('timestamp is missing');
  });

  it('rejects a block time that is not whole seconds', async () => {
    const response = readTxResponse({ blockRef: point({ timestamp: 1_700_000_000_500n }) });
    await expect(read(sourceWith({ response }))).rejects.toThrow('whole seconds');
  });

  it('rejects a non-uint32 output index', async () => {
    await expect(
      readRawEvent({ source: sourceWith(), txHash: TX_HASH, outputIndex: -1 }),
    ).rejects.toThrow('uint32');
    await expect(
      readRawEvent({ source: sourceWith(), txHash: TX_HASH, outputIndex: 2 ** 32 }),
    ).rejects.toThrow('uint32');
  });

  it('rejects a transaction hash that is not 64 lowercase hex characters', async () => {
    await expect(
      readRawEvent({ source: sourceWith(), txHash: TX_HASH.toUpperCase(), outputIndex: 0 }),
    ).rejects.toThrow('64 lowercase hex');
  });

  it('rejects a read whose assets do not fit the observation schema', async () => {
    const badAsset = output({
      assets: [
        new cardano.Multiasset({
          policyId: Uint8Array.from({ length: 32 }, () => 0xab),
          assets: [
            new cardano.Asset({
              name: Uint8Array.from([0xcd]),
              quantity: { case: 'outputCoin', value: coin(1n) },
            }),
          ],
        }),
      ],
    });
    await expect(
      read(sourceWith({ response: readTxResponse({ outputs: [badAsset] }) })),
    ).rejects.toThrow('56 lowercase hex');
  });
});

describe('bech32AddressOf', () => {
  it('encodes a testnet payment address above the default bech32 length limit', () => {
    expect(bech32AddressOf(ADDRESS_BYTES)).toBe(ADDRESS);
  });

  it('uses the mainnet prefix for a mainnet network id', () => {
    const mainnet = new Uint8Array(57);
    mainnet[0] = 0x01;
    expect(bech32AddressOf(mainnet)).toBe(
      'addr1qyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqv2t5am',
    );
  });

  it('rejects a non-payment address type', () => {
    const stake = new Uint8Array(57);
    stake[0] = 0xe0;
    expect(() => bech32AddressOf(stake)).toThrow('not a payment address');
  });

  it('rejects a payment address with the wrong length', () => {
    expect(() => bech32AddressOf(new Uint8Array(28))).toThrow('must be 57 bytes');
    expect(() => bech32AddressOf(new Uint8Array(56))).toThrow('must be 57 bytes');
    const enterprise = new Uint8Array(28);
    enterprise[0] = 0x60;
    expect(() => bech32AddressOf(enterprise)).toThrow('must be 29 bytes');
  });

  it('rejects an empty address', () => {
    expect(() => bech32AddressOf(new Uint8Array())).toThrow('empty');
  });
});

describe('lovelaceOf', () => {
  it('reads an int amount', () => {
    expect(lovelaceOf(coin(5_000_000n))).toBe(5_000_000n);
  });

  it('reads a big-uint amount', () => {
    const big = new cardano.BigInt({
      bigInt: { case: 'bigUInt', value: Uint8Array.from([0x01, 0x00]) },
    });
    expect(lovelaceOf(big)).toBe(256n);
  });

  it('rejects an absent or negative amount', () => {
    expect(() => lovelaceOf(undefined)).toThrow('has no amount');
    expect(() => lovelaceOf(coin(-1n))).toThrow('negative');
    const negative = new cardano.BigInt({
      bigInt: { case: 'bigNInt', value: Uint8Array.from([0x01]) },
    });
    expect(() => lovelaceOf(negative)).toThrow('negative');
  });
});

describe('createDolosSource', () => {
  it('builds a source with the four calls', () => {
    const source = createDolosSource({ uri: 'http://127.0.0.1:50051' });
    expect(typeof source.readTx).toBe('function');
    expect(typeof source.readGenesis).toBe('function');
    expect(typeof source.readTip).toBe('function');
    expect(typeof source.fetchBlock).toBe('function');
  });
});
