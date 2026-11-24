// The Dolos UTxO-RPC source: reads one Cardano transaction, its block and the
// chain tip, and returns the kind's validated observation.

import { CardanoQueryClient, CardanoSyncClient } from '@utxorpc/sdk';
import type { cardano, query } from '@utxorpc/spec';
import { bech32 } from 'bech32';
import { bytes32OfHex, bytesToHex, MAX_UINT32 } from '../bytes.js';
import { cardanoOutputObservationSchema, type OutputObservation } from '../output/index.js';

/** Connection options for {@link createDolosSource}. */
export interface DolosSourceOptions {
  /** The gRPC base URL, such as `http://localhost:50051`. */
  uri: string;
  /** Headers for an authenticated endpoint. */
  headers?: Record<string, string>;
}

/** A UTxO-RPC endpoint the reader queries, narrowed to the calls it makes. */
export interface DolosSource {
  /** Read one transaction and its block reference. */
  readTx(hash: Uint8Array): Promise<query.ReadTxResponse>;
  /** Read the network's genesis, which carries its magic. */
  readGenesis(): Promise<cardano.Genesis>;
  /** Read the current chain tip. */
  readTip(): Promise<{ slot: bigint; hash: Uint8Array }>;
  /** Read the block at `ref`. */
  fetchBlock(ref: { slot: bigint; hash: Uint8Array }): Promise<cardano.Block>;
}

/**
 * Build a {@link DolosSource} from a UTxO-RPC endpoint.
 *
 * The source makes one query per call; it holds no cache and no policy.
 */
export const createDolosSource = (options: DolosSourceOptions): DolosSource => {
  const queryClient = new CardanoQueryClient(options);
  const syncClient = new CardanoSyncClient(options);
  return {
    // The SDK's generated type wants an ArrayBuffer-backed view; copy the
    // caller's bytes so a shared buffer cannot leak across the RPC boundary.
    readTx: (hash) => queryClient.inner.readTx({ hash: new Uint8Array(hash) }),
    readGenesis: () => queryClient.readGenesis(),
    readTip: async () => {
      const tip = await syncClient.readTip();
      return { slot: BigInt(tip.slot), hash: bytes32OfHex(tip.hash) };
    },
    fetchBlock: async (ref) => {
      const block = await syncClient.fetchBlock({
        slot: ref.slot.toString(),
        hash: bytesToHex(ref.hash),
      });
      return block.parsedBlock;
    },
  };
};

/** Reject a bigint that a JavaScript number cannot hold exactly. */
const safeNumberOf = (value: bigint, name: string): number => {
  const number = Number(value);
  if (!Number.isSafeInteger(number) || number < 0) {
    throw new Error(`${name} ${value} is outside the safe integer range`);
  }
  return number;
};

/** Encode a 32-byte hash as lowercase hex. */
const hashHexOf = (bytes: Uint8Array, name: string): string => {
  if (bytes.length !== 32) {
    throw new Error(`${name} must be 32 bytes, got ${bytes.length}`);
  }
  return bytesToHex(bytes);
};

/**
 * Encode a CIP-19 payment address from its raw bytes.
 *
 * @throws if the bytes are empty, not a payment address, or carry an unknown
 *   network id.
 */
export const bech32AddressOf = (bytes: Uint8Array): string => {
  const header = bytes[0];
  if (header === undefined) {
    throw new Error('output address is empty');
  }
  const type = header >> 4;
  // Byron-era addresses (header 0x82...) are rejected: they use a CBOR
  // encoding, never bech32, so this reader cannot attest their outputs.
  if (type > 7) {
    throw new Error(`output address type ${type} is not a payment address`);
  }
  // CIP-19: types 0-3 are base addresses (57 bytes), 4-5 are pointer
  // addresses (29 bytes plus a variable pointer), 6-7 are enterprise
  // addresses (29 bytes).
  if (type <= 3 && bytes.length !== 57) {
    throw new Error(`output address type ${type} must be 57 bytes, got ${bytes.length}`);
  }
  if (type >= 6 && bytes.length !== 29) {
    throw new Error(`output address type ${type} must be 29 bytes, got ${bytes.length}`);
  }
  if (type >= 4 && type <= 5 && bytes.length < 29) {
    throw new Error(`output address type ${type} must be at least 29 bytes, got ${bytes.length}`);
  }
  const networkId = header & 0x0f;
  const hrp = networkId === 0 ? 'addr_test' : networkId === 1 ? 'addr' : undefined;
  if (hrp === undefined) {
    throw new Error(`output address network id ${networkId} is not known`);
  }
  // Cardano base addresses exceed bech32's default 90-character limit.
  return bech32.encode(hrp, bech32.toWords(bytes), 1000);
};

/** Read a uint64 amount from the UTxO-RPC `BigInt` oneof. */
const uint64Of = (coin: cardano.BigInt | undefined, what: string): bigint => {
  if (!coin) {
    throw new Error(`${what} has no amount`);
  }
  switch (coin.bigInt.case) {
    case 'int':
      if (coin.bigInt.value < 0n) {
        throw new Error(`${what} ${coin.bigInt.value} is negative`);
      }
      return coin.bigInt.value;
    case 'bigUInt':
      return BigInt(`0x${bytesToHex(coin.bigInt.value)}`);
    default:
      throw new Error(`${what} is negative or missing`);
  }
};

/**
 * Read a lovelace amount from the UTxO-RPC `BigInt` oneof.
 *
 * @throws if the amount is absent or negative.
 */
export const lovelaceOf = (coin: cardano.BigInt | undefined): bigint =>
  uint64Of(coin, 'output lovelace');

/**
 * Read one output and its block from a UTxO-RPC source, as the kind's
 * observation, validated by its schema. The source is trusted to describe its
 * own chain (ADR 0003); the reader checks the response's transaction hash
 * against the requested one, so an endpoint that answers a different query is
 * caught here.
 *
 * @throws if the transaction is missing, not Cardano, carries no hash or a
 *   hash other than the requested one, failed, has no such output or block
 *   reference, the genesis magic is missing, the block time is missing or not
 *   whole seconds, or the tip block has no header.
 * @throws `ZodError` if the result does not fit the observation schema.
 */
export const readOutputObservation = async (options: {
  source: DolosSource;
  /** The transaction hash, 64 lowercase hex characters. */
  txHash: string;
  /** The output's index within the transaction, a uint32. */
  outputIndex: number;
}): Promise<OutputObservation> => {
  const { source, txHash, outputIndex } = options;
  if (!Number.isInteger(outputIndex) || outputIndex < 0 || outputIndex > MAX_UINT32) {
    throw new Error(`output index must be a uint32, got ${outputIndex}`);
  }

  const response = await source.readTx(bytes32OfHex(txHash));
  const anyTx = response.tx;
  if (!anyTx) {
    throw new Error('readTx returned no transaction');
  }
  if (anyTx.chain.case !== 'cardano') {
    throw new Error('readTx returned a non-Cardano transaction');
  }
  const tx = anyTx.chain.value;
  // The response carries its transaction's hash; require it to be the one the
  // caller asked for, so an endpoint cannot answer with another transaction.
  if (tx.hash.length !== 32) {
    throw new Error(`transaction ${txHash} response carries no hash`);
  }
  if (bytesToHex(tx.hash) !== txHash) {
    throw new Error(`response is transaction ${bytesToHex(tx.hash)}, not ${txHash}`);
  }
  if (!tx.successful) {
    throw new Error(`transaction ${txHash} is not successful`);
  }
  const output = tx.outputs[outputIndex];
  if (!output) {
    throw new Error(`transaction ${txHash} has no output ${outputIndex}`);
  }
  const blockRef = anyTx.blockRef;
  if (!blockRef) {
    throw new Error(`transaction ${txHash} has no block reference`);
  }
  const genesis = await source.readGenesis();
  if (!Number.isInteger(genesis.networkMagic) || genesis.networkMagic < 1) {
    throw new Error(`readGenesis returned network magic ${genesis.networkMagic}`);
  }

  const tipPoint = response.ledgerTip ?? (await source.readTip());
  const tipBlock = await source.fetchBlock({ slot: tipPoint.slot, hash: tipPoint.hash });
  const tipHeader = tipBlock.header;
  if (!tipHeader) {
    throw new Error('tip block has no header');
  }

  if (blockRef.timestamp === 0n) {
    throw new Error('block timestamp is missing');
  }
  // UTxO-RPC decodes an unset height or slot as 0. No transaction lives in the
  // genesis block, and a zero height would pass any depth check.
  if (blockRef.height === 0n) {
    throw new Error('block height is missing');
  }
  if (blockRef.slot === 0n) {
    throw new Error('block slot is missing');
  }
  if (blockRef.timestamp % 1000n !== 0n) {
    throw new Error(`block timestamp ${blockRef.timestamp} is not whole seconds`);
  }

  return cardanoOutputObservationSchema.parse({
    networkMagic: genesis.networkMagic,
    tipBlockNumber: safeNumberOf(tipHeader.height, 'tip block height'),
    block: {
      hash: hashHexOf(blockRef.hash, 'block hash'),
      slot: safeNumberOf(blockRef.slot, 'block slot'),
      blockNumber: safeNumberOf(blockRef.height, 'block height'),
      time: safeNumberOf(blockRef.timestamp / 1000n, 'block time'),
    },
    output: {
      txHash,
      outputIndex,
      address: bech32AddressOf(output.address),
      lovelace: lovelaceOf(output.coin),
      assets: output.assets.flatMap((multiasset) =>
        multiasset.assets.map((asset) => ({
          policyId: bytesToHex(multiasset.policyId),
          assetName: bytesToHex(asset.name),
          quantity: uint64Of(asset.quantity.value, 'output asset quantity'),
        })),
      ),
    },
  });
};
