// Live endpoint check: one real UTxO-RPC endpoint reads a Cardano output and a
// real attestor signs the claim through the client; opt-in via `DOLOS_URL`.

import { randomBytes } from 'node:crypto';
import {
  CompactTypeField,
  CompactTypeVector,
  type JubjubPoint,
  type JubjubSchnorrSignature,
  jubjubSchnorrSign,
  jubjubSchnorrVerifyingKey,
  sampleJubjubSchnorrSk,
} from '@midnight-ntwrk/compact-runtime';
import type { KeyPair } from '@txpipe/thoth-attestor';
import { descriptorOf } from '@txpipe/thoth-attestor';
import {
  type CardanoNetwork,
  type CardanoObservation,
  type CardanoPolicy,
  cardanoOutputSaltOf,
  cardanoOutputSubjectHashOf,
  cardanoPolicyHashOf,
} from '@txpipe/thoth-cardano';
import { cardanoAttestor } from '@txpipe/thoth-cardano/attestor';
import { type CardanoAttestationInput, cardanoClient } from '@txpipe/thoth-cardano/client';
import {
  createDolosSource,
  type DolosSource,
  readOutputObservation,
} from '@txpipe/thoth-cardano/dolos';
import { buildTrustedSet } from '@txpipe/thoth-client';
import { jubjubVerifier } from '@txpipe/thoth-client/jubjub';
import { claimToMessage } from '@txpipe/thoth-core/claim';
import { holderCommitmentOf } from '@txpipe/thoth-core/claim-context';
import { describe, expect, it } from 'vitest';

/** The recorded preview event the fixture suite reads; override for another one. */
const DEFAULT_TX_HASH = '65d12c1a8204919d850739e9edac795dd69afcf09fd6d77d85c1ffae76fdfe8f';

const ENDPOINT = process.env.DOLOS_URL?.trim() ?? '';
const TX_HASH = process.env.CARDANO_TX_HASH?.trim() || DEFAULT_TX_HASH;
const OUTPUT_INDEX = Number(process.env.CARDANO_OUTPUT_INDEX ?? 0);
const CONFIRMATION_DEPTH = Number(process.env.CARDANO_CONFIRMATION_DEPTH ?? 0);

/** Authenticated endpoints (Demeter, for example) take their key in a header. */
const headersOf = (): Record<string, string> | undefined =>
  process.env.DOLOS_HEADERS
    ? (JSON.parse(process.env.DOLOS_HEADERS) as Record<string, string>)
    : undefined;

const NETWORK_BY_MAGIC = new Map<number, CardanoNetwork>([
  [764824073, 'mainnet'],
  [2, 'preview'],
  [1, 'preprod'],
]);

const APP_ID = new Uint8Array(32).fill(0xa1);

/** The policy derived from the event itself: its address, chain and slot map. */
const policyOf = (observation: CardanoObservation): CardanoPolicy => ({
  kind: 'output',
  network: NETWORK_BY_MAGIC.get(observation.networkMagic) ?? 'devnet',
  networkMagic: observation.networkMagic,
  confirmationDepth: CONFIRMATION_DEPTH,
  address: observation.output.address,
  slots: [
    { slot: 0, name: 'lovelace' },
    { slot: 1, name: 'blockNumber' },
    { slot: 2, name: 'txHash' },
  ],
});

const keyPairOf = (): KeyPair<JubjubPoint, JubjubSchnorrSignature> => {
  const sk = sampleJubjubSchnorrSk();
  return {
    publicKey: jubjubSchnorrVerifyingKey(sk),
    signer: {
      sign: (message) =>
        jubjubSchnorrSign(
          new CompactTypeVector(message.length, CompactTypeField),
          [...message],
          sk,
        ),
    },
  };
};

/** Read the event, naming the setting to try when the endpoint cannot serve it. */
const readFrom = async (source: DolosSource): Promise<CardanoObservation> => {
  try {
    return await readOutputObservation({ source, txHash: TX_HASH, outputIndex: OUTPUT_INDEX });
  } catch (error) {
    throw new Error(
      `endpoint could not read ${TX_HASH}:${OUTPUT_INDEX}; ` +
        'set CARDANO_TX_HASH to an event it retains',
      { cause: error },
    );
  }
};

describe.skipIf(ENDPOINT === '')('live UTxO-RPC endpoint', () => {
  it('signs one claim from a live read', async () => {
    const source = createDolosSource({ uri: ENDPOINT, headers: headersOf() });
    const locator = { txHash: TX_HASH, outputIndex: OUTPUT_INDEX };

    const observed = await readFrom(source);
    const policy = policyOf(observed);
    const attestor = cardanoAttestor({
      id: 'live-endpoint',
      keyPair: keyPairOf(),
      read: (event) => readOutputObservation({ source, ...event }),
    });
    const holderSecret = randomBytes(32);
    const holder = holderCommitmentOf(holderSecret);
    const client = cardanoClient.init({
      trusted: buildTrustedSet({
        registrySize: 1,
        attestors: [{ attestor: descriptorOf(attestor), registryIndex: 0 }],
      }),
      transport: {
        request: (descriptor, input) => {
          if (descriptor.id !== attestor.id) {
            throw new Error(`unknown attestor ${descriptor.id}`);
          }
          return attestor.attest(input as CardanoAttestationInput);
        },
      },
      verifier: jubjubVerifier,
      policy,
      appId: APP_ID,
      valueSlots: 2,
      byteSlots: 1,
      read: () => observed,
    });

    const attestment = await client.collect(locator, {
      holder,
      expiresAt: Date.now() + 120_000,
      threshold: 1,
      attestorTimeoutMs: 60_000,
    });

    // The attestor derives the claim from its own live read; collection only
    // passes when that read agrees with the client's and the signature verifies.
    expect(attestment.failures).toEqual([]);
    expect(attestment.collected.map((entry) => entry.registryIndex)).toEqual([0]);

    const { claim } = attestment;
    expect(claim.appId).toEqual(APP_ID);
    expect(claim.holder).toEqual(holder);
    expect(claim.policyHash).toEqual(cardanoPolicyHashOf(policy));
    expect(claim.windowStart).toBe(BigInt(observed.block.time));
    expect(claim.windowEnd).toBe(BigInt(observed.block.time));
    expect(claim.subjectHash).toEqual(
      cardanoOutputSubjectHashOf({
        networkMagic: observed.networkMagic,
        txHash: TX_HASH,
        outputIndex: OUTPUT_INDEX,
        blockHash: observed.block.hash,
      }),
    );
    expect(claim.salt).toEqual(cardanoOutputSaltOf(observed.networkMagic, TX_HASH, OUTPUT_INDEX));
    expect(claim.present).toEqual([true, true, true]);
    expect(claim.values).toEqual([observed.output.lovelace, BigInt(observed.block.blockNumber)]);
    expect(claim.byteValues.map((value) => Buffer.from(value).toString('hex'))).toEqual([TX_HASH]);
    for (const entry of attestment.collected) {
      expect(entry.attestation.message).toEqual(claimToMessage(claim));
    }
  }, 180_000);
});
