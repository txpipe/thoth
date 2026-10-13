// Hermes's side of a live claim: prove the request through each attestor's witness, then
// collect a 2-of-3 attestment from the attestors over HTTP, laid out at the Bounty's
// registry slots. Only Hermes holds the City token; the client checks no evidence carries it.
import { randomBytes } from 'node:crypto';
import type { JubjubPoint, JubjubSchnorrSignature } from '@midnight-ntwrk/compact-runtime';
import { buildTrustedSet } from '@thoth/client';
import { jubjubVerifier } from '@thoth/client/jubjub';
import type { ZkFetchPolicy } from '@thoth/zk-tls';
import { createZkFetchDefinition } from '@thoth/zk-tls/attestor';
import { type ZkFetchRequest, zkFetchClient } from '@thoth/zk-tls/client';
import { zkFetchProver } from '@thoth/zk-tls/prover';
import type { Attestation } from './bounty-client.js';
import { decode, encode } from './wire.js';

/** An attestor Hermes's operator trusts, and the witness it trusts. */
export interface AttestorEndpoint {
  url: string;
  witnessUrl: string;
}

type Descriptor = { id: string; publicKey: JubjubPoint };

/** A signature that never verifies, for a registry slot nobody signs. */
const UNSIGNED: JubjubSchnorrSignature = { announcement: { x: 0n, y: 1n }, response: 0n };

const samePoint = (a: JubjubPoint, b: JubjubPoint): boolean => a.x === b.x && a.y === b.y;

/**
 * Each endpoint's attestor, and its slot among the Bounty's pinned keys.
 *
 * @param endpoints - the attestors to use.
 * @param registryKeys - the keys the Bounty pinned at deploy.
 * @returns each attestor's id, key, slot and witness.
 * @throws if an attestor's key isn't one the Bounty pinned.
 */
export const resolveAttestors = async (
  endpoints: readonly AttestorEndpoint[],
  registryKeys: readonly JubjubPoint[],
) =>
  Promise.all(
    endpoints.map(async (endpoint) => {
      const descriptor = decode(
        await (await fetch(`${endpoint.url}/descriptor`)).text(),
      ) as Descriptor;
      const registryIndex = registryKeys.findIndex((key) => samePoint(key, descriptor.publicKey));
      if (registryIndex < 0) {
        throw new Error(
          `attestor ${descriptor.id} at ${endpoint.url} isn't one this Bounty pinned`,
        );
      }
      return { ...descriptor, registryIndex, ...endpoint };
    }),
  );

/**
 * Prove `request` live and collect a 2-of-3 attestment of it under `policy`.
 *
 * @param options - what to prove, under which policy, for which holder and window.
 * @returns the attestation, ready to vault in the Bounty.
 */
export const collectClaim = async (options: {
  request: ZkFetchRequest;
  policy: ZkFetchPolicy;
  holder: Uint8Array;
  window: readonly [bigint, bigint];
  attestors: Awaited<ReturnType<typeof resolveAttestors>>;
  registryKeys: readonly JubjubPoint[];
}): Promise<Attestation> => {
  const definition = createZkFetchDefinition();
  const byId = new Map(options.attestors.map((attestor) => [attestor.id, attestor]));
  const client = zkFetchClient.init({
    trusted: buildTrustedSet({
      registrySize: options.registryKeys.length,
      attestors: options.attestors.map(({ id, publicKey, registryIndex }) => ({
        attestor: { id, definition, publicKey },
        registryIndex,
      })),
    }),
    verifier: jubjubVerifier,
    transport: {
      request: async (descriptor, input) => {
        const url = byId.get(descriptor.id)?.url;
        const response = await fetch(`${url}/attest`, { method: 'POST', body: encode(input) });
        const body = decode(await response.text()) as { error?: string };
        if (!response.ok) {
          throw new Error(`attestor ${descriptor.id} refused: ${body.error}`);
        }
        return body as never;
      },
    },
    policy: options.policy,
    appId: new Uint8Array(32).fill(0xa1),
    valueSlots: 6,
    provers: Object.fromEntries(
      options.attestors.map(({ id, witnessUrl }) => [id, zkFetchProver({ witnessUrl })]),
    ),
  });
  const { claim, collected } = await client.collect(options.request, {
    holder: options.holder,
    windowStart: options.window[0],
    windowEnd: options.window[1],
    expiresAt: Date.now() + 120_000,
    threshold: 2,
    attestorTimeoutMs: 60_000,
  });
  return {
    claim: { ...claim, present: [...claim.present], values: [...claim.values] },
    signatures: options.registryKeys.map(
      (_, slot) =>
        collected.find((entry) => entry.registryIndex === slot)?.attestation.signature ?? UNSIGNED,
    ),
    commitRand: randomBytes(32),
  };
};
