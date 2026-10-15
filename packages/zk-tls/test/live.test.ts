// Live cross-witness check: two real Reclaim witnesses fetch the same request
// and must derive one claim. Opt-in through `WITNESS_URLS`, skipped otherwise
// (`npm test` stays offline and deterministic). See the README's "Live check".
import { claimToMessage } from '@thoth/core/claim';
import {
  assertEvidenceMatchesPolicy,
  deriveClaimFromEvidence,
  parseDisclosedValue,
  type ZkFetchPolicy,
} from '@thoth/zk-tls';
import { verifyZkFetchProof } from '@thoth/zk-tls/attestor';
import { zkFetchProver } from '@thoth/zk-tls/prover';
import { describe, expect, it } from 'vitest';

/** The app id every claim in this suite is for. */
const APP_ID = new Uint8Array(32).fill(0xa1);

const WITNESS_URLS = (process.env.WITNESS_URLS ?? '')
  .split(',')
  .map((url) => url.trim())
  .filter((url) => url !== '');
const TARGET_URL = process.env.LIVE_URL ?? 'https://api.github.com/repos/txpipe/dolos';

const RESPONSE_MATCH = { type: 'regex' as const, value: '"stargazers_count":\\s*(?<stars>\\d+)' };
const RESPONSE_REDACTION = { regex: '"stargazers_count":\\s*\\d+' };

const policy: ZkFetchPolicy = {
  allowedHosts: ['api.github.com'],
  slots: [{ slot: 0, name: 'stars', parse: 'int' }],
  responseMatches: [RESPONSE_MATCH],
  responseRedactions: [RESPONSE_REDACTION],
};

describe.skipIf(WITNESS_URLS.length < 2)('live witnesses', () => {
  it('agree on one claim over a shared fetch', async () => {
    const request = {
      url: TARGET_URL,
      method: 'GET' as const,
      context: { label: 'thoth-live-check' },
      // Reveal only the star count: whole responses carry per-request headers
      // (rate limits, dates, request ids) that make witnesses disagree.
      responseMatches: [RESPONSE_MATCH],
      responseRedactions: [RESPONSE_REDACTION],
    };
    const evidences = await Promise.all(
      WITNESS_URLS.map((witnessUrl) => zkFetchProver({ witnessUrl }).prove(request)),
    );
    const verified = await Promise.all(evidences.map((evidence) => verifyZkFetchProof(evidence)));
    for (const view of verified) {
      assertEvidenceMatchesPolicy(view, policy);
    }

    expect(new Set(verified.map((view) => view.identifier)).size).toBe(1);

    const observedAt = evidences.map((evidence) => evidence.claim.timestampS);
    const windowStart = BigInt(Math.min(...observedAt));
    const windowEnd = BigInt(Math.max(...observedAt));
    const messages = verified.map((view) =>
      claimToMessage(
        deriveClaimFromEvidence({
          verified: view,
          policy,
          appId: APP_ID,
          holder: new Uint8Array(32).fill(0xc1),
          valueSlots: 1,
          windowStart,
          windowEnd,
        }),
      ),
    );
    expect(new Set(messages.map((message) => message.join(','))).size).toBe(1);

    // The star count is mutable, so assert it is present and sane, not exact.
    const stars = verified.map((view) =>
      parseDisclosedValue(view.disclosedValues.stars ?? '', 'int'),
    );
    expect(stars.every((value) => value !== null && value > 0n)).toBe(true);
  }, 180_000);
});
