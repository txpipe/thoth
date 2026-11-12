// What zkFetch exports to tooling: the object the `thoth` CLI drives zkFetch
// through. It loads the attestor side, so a dApp imports `./client` instead.
import { createHash } from 'node:crypto';
import { defineKind, denseLayout, type KindAttestorKey } from '@thoth/core/kind';
import { zkFetchAttestor } from '../attestor/index.js';
import { type ZkFetchProver, zkTlsKindClient } from '../client/index.js';
import { testWitness } from '../dev/index.js';
import {
  isByteRule,
  normalizePolicy,
  type ZkFetchLimits,
  type ZkFetchPolicy,
  zkFetchPolicyHashOf,
  zkFetchPolicySchema,
} from '../index.js';

/** One zkFetch operator's trust anchors: what its attestor takes besides its id and key. */
export interface ZkFetchAttestorAnchors {
  /** The operator's own Reclaim witness address, `0x` + 40 hex. */
  readonly witnessAddress: string;
  /** The attestor's input limits, merged over `ZK_FETCH_DEFAULT_LIMITS`. */
  readonly limits?: Partial<ZkFetchLimits>;
}

/** What every offline zkFetch witness observes. */
export interface ZkFetchDevInput {
  /** The disclosed values, keyed by the policy's named groups. */
  readonly values: Readonly<Record<string, string>>;
  /** The observation time, Unix seconds. */
  readonly timestampS: number;
}

/**
 * The object tooling drives zkFetch through, a `KindManifest`. Keys and
 * signatures are Jubjub Schnorr.
 *
 * `layoutOf` applies `denseLayout` from `@thoth/core/kind`. `devEvidence`
 * gives each operator a fixed test witness key, so its evidence proves
 * nothing: use it only offline.
 */
export const zkTls = defineKind({
  ...zkTlsKindClient,
  clientEntry: { module: '@thoth/zk-tls/client', export: 'zkTlsKindClient' },
  policySchema: zkFetchPolicySchema,
  policyHashOf: zkFetchPolicyHashOf,
  layoutOf: (policy: ZkFetchPolicy) =>
    denseLayout(
      normalizePolicy(policy).slots.map((slot) => ({
        slot: slot.slot,
        name: slot.name,
        region: isByteRule(slot.parse) ? 'bytes' : 'numeric',
        optional: slot.optional,
      })),
    ),
  attestor: (config: KindAttestorKey & ZkFetchAttestorAnchors) => zkFetchAttestor(config),
  devEvidence: (policy: ZkFetchPolicy, operators: number, input: ZkFetchDevInput) => {
    const { responseMatches, responseRedactions } = normalizePolicy(policy);
    if (!Number.isSafeInteger(operators) || operators < 1) {
      throw new Error(`operators must be a positive integer, got ${operators}`);
    }
    return Array.from({ length: operators }, (_, i) => {
      const key = createHash('sha256').update(`thoth-dev-witness:${i}`).digest('hex');
      const witness = testWitness(`0x${key}`);
      const prover: ZkFetchProver = {
        // Signs what the request asks for, as a real witness does. The client
        // always binds the policy's rules into the request first.
        prove: (request) =>
          witness.sign({
            values: input.values,
            timestampS: input.timestampS,
            parameters: {
              url: request.url,
              method: request.method ?? 'GET',
              body: request.body ?? '',
              responseMatches: request.responseMatches ?? responseMatches,
              responseRedactions: request.responseRedactions ?? responseRedactions,
            },
            context: request.context,
          }),
      };
      const attestorConfig: ZkFetchAttestorAnchors = { witnessAddress: witness.address };
      return { attestorConfig, prover };
    });
  },
});
