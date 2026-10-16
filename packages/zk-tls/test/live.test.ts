// Live cross-witness check: two real Reclaim witnesses fetch the same request,
// sign its claim context digest, and must derive one claim — once
// numeric-only, once with a byte value slot.
// Opt-in through `WITNESS_URLS`, skipped otherwise (`npm test` stays offline
// and deterministic). See the README's "Live check".
import { claimToMessage } from '@thoth/core/claim';
import {
  assertEvidenceMatchesPolicy,
  deriveClaimFromEvidence,
  parseDisclosedValue,
  ZK_FETCH_CLAIM_CONTEXT_KEY,
  type ZkFetchPolicy,
  zkFetchClaimContextDigestOf,
} from '@thoth/zk-tls';
import { assertClaimMatchesContext, verifyZkFetchProof } from '@thoth/zk-tls/attestor';
import type { ZkFetchRequest } from '@thoth/zk-tls/client';
import { zkFetchProver } from '@thoth/zk-tls/prover';
import { describe, expect, it } from 'vitest';

/** The app id every claim in this suite is for. */
const APP_ID = new Uint8Array(32).fill(0xa1);
/** The holder every claim in this suite is for. */
const HOLDER = new Uint8Array(32).fill(0xc1);

// Derivation reads the salt from this digest. No attestor runs here, so nothing
// checks it against a holder or window.
const SIGNED_DIGEST = { [ZK_FETCH_CLAIM_CONTEXT_KEY]: 'cd'.repeat(32) };

const WITNESS_URLS = (process.env.WITNESS_URLS ?? '')
  .split(',')
  .map((url) => url.trim())
  .filter((url) => url !== '');
const TARGET_URL = process.env.LIVE_URL ?? 'https://api.github.com/repos/txpipe/dolos';

const RESPONSE_MATCH = { type: 'regex' as const, value: '"stargazers_count":\\s*(?<stars>\\d+)' };
const RESPONSE_REDACTION = { regex: '"stargazers_count":\\s*\\d+' };
const NAME_MATCH = { type: 'regex' as const, value: '"full_name":\\s*"(?<name>[^"]+)"' };
const NAME_REDACTION = { regex: '"full_name":\\s*"[^"]*"' };

const policy: ZkFetchPolicy = {
  allowedHosts: ['api.github.com'],
  slots: [{ slot: 0, name: 'stars', parse: 'int' }],
  responseMatches: [RESPONSE_MATCH],
  responseRedactions: [RESPONSE_REDACTION],
};

// V = 1 numeric slot (stars) then W = 1 byte slot (the repo's "owner/repo").
const mixedPolicy: ZkFetchPolicy = {
  allowedHosts: ['api.github.com'],
  slots: [
    { slot: 0, name: 'stars', parse: 'int' },
    { slot: 1, name: 'name', parse: 'bytes' },
  ],
  responseMatches: [RESPONSE_MATCH, NAME_MATCH],
  responseRedactions: [RESPONSE_REDACTION, NAME_REDACTION],
};

/**
 * Prove `request` with every configured witness, under the claim context
 * digest of `signedPolicy`, {@link HOLDER} and a window fixed up front, and
 * verify each response.
 *
 * @param request — the request every witness must fetch verbatim.
 * @returns the verified views and the window.
 */
const proveAndVerify = async (request: ZkFetchRequest, signedPolicy: ZkFetchPolicy) => {
  const now = BigInt(Math.floor(Date.now() / 1000));
  const windowStart = now - 60n;
  const windowEnd = now + 600n;
  const digest = zkFetchClaimContextDigestOf({
    policy: signedPolicy,
    request: { method: request.method ?? 'GET', url: request.url, body: request.body },
    holder: HOLDER,
    windowStart,
    windowEnd,
  });
  const bound = {
    ...request,
    context: { ...request.context, [ZK_FETCH_CLAIM_CONTEXT_KEY]: digest },
  };
  const evidences = await Promise.all(
    WITNESS_URLS.map((witnessUrl) => zkFetchProver({ witnessUrl }).prove(bound)),
  );
  const verified = await Promise.all(evidences.map((evidence) => verifyZkFetchProof(evidence)));
  return { verified, windowStart, windowEnd };
};

describe.skipIf(WITNESS_URLS.length < 2)('live witnesses', () => {
  it('agree on one claim over a shared fetch', async () => {
    const request = {
      url: TARGET_URL,
      method: 'GET' as const,
      context: { label: 'thoth-live-check', ...SIGNED_DIGEST },
      // Reveal only the star count: whole responses carry per-request headers
      // (rate limits, dates, request ids) that make witnesses disagree.
      responseMatches: [RESPONSE_MATCH],
      responseRedactions: [RESPONSE_REDACTION],
    };
    const { verified, windowStart, windowEnd } = await proveAndVerify(request, policy);
    for (const view of verified) {
      assertEvidenceMatchesPolicy(view, policy);
    }

    expect(new Set(verified.map((view) => view.identifier)).size).toBe(1);

    const messages = verified.map((view) => {
      const claim = deriveClaimFromEvidence({
        verified: view,
        policy,
        appId: APP_ID,
        holder: HOLDER,
        valueSlots: 1,
        windowStart,
        windowEnd,
      });
      // A real witness keeps the client's context keys next to its own.
      assertClaimMatchesContext({ claim, verified: view, policy });
      return claimToMessage(claim);
    });
    expect(new Set(messages.map((message) => message.join(','))).size).toBe(1);

    // The star count is mutable, so assert it is present and sane, not exact.
    const stars = verified.map((view) =>
      parseDisclosedValue(view.disclosedValues.stars ?? '', 'int'),
    );
    expect(stars.every((value) => value !== null && value > 0n)).toBe(true);
  }, 180_000);

  it('agree on one claim carrying a byte value', async () => {
    const request = {
      url: TARGET_URL,
      method: 'GET' as const,
      context: { label: 'thoth-live-bytes-check', ...SIGNED_DIGEST },
      responseMatches: [RESPONSE_MATCH, NAME_MATCH],
      responseRedactions: [RESPONSE_REDACTION, NAME_REDACTION],
    };
    const { verified, windowStart, windowEnd } = await proveAndVerify(request, mixedPolicy);
    for (const view of verified) {
      assertEvidenceMatchesPolicy(view, mixedPolicy);
    }

    expect(new Set(verified.map((view) => view.identifier)).size).toBe(1);

    const claims = verified.map((view) => {
      const claim = deriveClaimFromEvidence({
        verified: view,
        policy: mixedPolicy,
        appId: APP_ID,
        holder: HOLDER,
        valueSlots: 1,
        byteSlots: 1,
        windowStart,
        windowEnd,
      });
      assertClaimMatchesContext({ claim, verified: view, policy: mixedPolicy });
      return claim;
    });
    const messages = claims.map((claim) => claimToMessage(claim));
    expect(new Set(messages.map((message) => message.join(','))).size).toBe(1);

    // The byte slot is present and carries the zero-padded UTF-8 of the
    // disclosed full name ("owner/repo"), identical across witnesses.
    const names = verified.map((view) =>
      parseDisclosedValue(view.disclosedValues.name ?? '', 'bytes'),
    );
    expect(names.every((name) => name !== null)).toBe(true);
    for (const claim of claims) {
      expect(claim.present).toEqual([true, true]);
    }
    const derived = claims.map((claim) => claim.byteValues[0]);
    expect(derived.map((value) => Buffer.from(value ?? []).toString('hex'))).toEqual(
      names.map((name) => Buffer.from(name ?? []).toString('hex')),
    );
  }, 180_000);
});
