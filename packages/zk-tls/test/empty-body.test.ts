// An empty signed body does not bind the body the witness sent: the receipt
// check skips the body comparison, so a caller can sign no body and send one.
import { randomBytes } from 'node:crypto';
import {
  CURRENT_ATTESTOR_VERSION,
  createClaimOnAttestor,
  logger,
  PROVIDER_CTX,
  providers,
  strToUint8Array,
  type Transcript,
} from '@reclaimprotocol/attestor-core';
import { setCryptoImplementation } from '@reclaimprotocol/tls';
import { webcryptoCrypto } from '@reclaimprotocol/tls/webcrypto';
import type { FlatMessage } from '@thoth/core/claim';
import {
  assertEvidenceMatchesPolicy,
  deriveClaimFromEvidence,
  ZK_FETCH_CLAIM_CONTEXT_KEY,
  type ZkFetchEvidence,
  type ZkFetchPolicy,
  zkFetchClaimContextDigestOf,
  zkFetchSubjectHashOf,
} from '@thoth/zk-tls';
import { verifyZkFetchProof, zkFetchAttestor } from '@thoth/zk-tls/attestor';
import { beforeAll, describe, expect, it } from 'vitest';

/** The app id every claim in this suite is for. */
const APP_ID = new Uint8Array(32).fill(0xa1);
/** The holder every claim in this suite is for. */
const HOLDER = new Uint8Array(32).fill(0xc1);

/** The body the live probe sends but does not sign. */
const PAYLOAD = { q: 123456789 };
const SENT_BODY = JSON.stringify(PAYLOAD);

/** The request the offline receipt check builds. */
const OFFLINE_URL = 'https://httpbin.org/post';
const OFFLINE_BODY = SENT_BODY;
const OFFLINE_REQUEST = [
  'POST /post HTTP/1.1',
  'Host: httpbin.org',
  'Connection: close',
  `Content-Length: ${Buffer.byteLength(OFFLINE_BODY)}`,
  'Accept-Encoding: identity',
  'Content-Type: application/json',
  '',
  OFFLINE_BODY,
].join('\r\n');
const OFFLINE_RESPONSE = 'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}';

const receipt = [
  { sender: 'client', message: strToUint8Array(OFFLINE_REQUEST) },
  { sender: 'server', message: strToUint8Array(OFFLINE_RESPONSE) },
] satisfies Transcript<Uint8Array>;

const receiptParams = (body: string) => ({
  url: OFFLINE_URL,
  method: 'POST' as const,
  body,
  responseMatches: [{ type: 'regex' as const, value: '(?<data>.*)' }],
  responseRedactions: [],
});

const checkReceipt = (body: string): unknown =>
  providers.http.assertValidProviderReceipt({
    clientVersion: CURRENT_ATTESTOR_VERSION,
    receipt,
    params: receiptParams(body),
    logger,
    ctx: PROVIDER_CTX,
  });

describe('Reclaim receipt check', () => {
  it('accepts a signed empty body when the request carries a body', () => {
    expect(() => checkReceipt('')).not.toThrow();
  });

  it('rejects a non-empty signed body that differs from the sent body', () => {
    expect(() => checkReceipt('not-the-sent-body')).toThrow('request body mismatch');
  });
});

const WITNESS_URLS = (process.env.WITNESS_URLS ?? '')
  .split(',')
  .map((url) => url.trim())
  .filter((url) => url !== '');
const WITNESS_URL = WITNESS_URLS[0] ?? '';
const PROBE_URL = process.env.PROBE_URL ?? 'https://httpbin.org/post';

/** The witness address endpoint next to its WebSocket endpoint. */
const witnessAddressOf = async (witnessUrl: string): Promise<string> => {
  const url = new URL(witnessUrl);
  url.protocol = url.protocol === 'wss:' ? 'https:' : 'http:';
  url.pathname = '/address';
  url.search = '';
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`witness address endpoint returned ${response.status}`);
  }
  const body = (await response.json()) as { address?: unknown };
  if (typeof body.address !== 'string') {
    throw new Error('witness address endpoint returned no address');
  }
  return body.address;
};

const hex = (bytes: Uint8Array): string => Buffer.from(bytes).toString('hex');

describe.skipIf(WITNESS_URL === '')('live witness', () => {
  beforeAll(() => {
    setCryptoImplementation(webcryptoCrypto);
  });

  it('signs an empty body while the sent body is non-empty, and Thoth refuses it', async () => {
    const policy: ZkFetchPolicy = {
      allowedHosts: [new URL(PROBE_URL).hostname],
      slots: [{ slot: 0, name: 'q', parse: 'int' }],
      responseMatches: [{ type: 'regex', value: '"q":\\s*(?<q>\\d+)' }],
      responseRedactions: [{ regex: '"q":\\s*\\d+' }],
    };
    const now = BigInt(Math.floor(Date.now() / 1000));
    const windowStart = now - 60n;
    const windowEnd = now + 600n;
    const signedRequest = { method: 'POST', url: PROBE_URL, body: '' };
    const digest = zkFetchClaimContextDigestOf({
      policy,
      request: signedRequest,
      holder: HOLDER,
      windowStart,
      windowEnd,
    });

    // `updateProviderParams` runs after the request is sent and before the
    // claim is signed, so the witness signs the empty body below while the
    // transcript still carries `SENT_BODY`.
    const result = await createClaimOnAttestor({
      name: 'http',
      params: {
        url: PROBE_URL,
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: SENT_BODY,
        responseMatches: policy.responseMatches.map((match) => ({ ...match })),
        responseRedactions: policy.responseRedactions.map((redaction) => ({ ...redaction })),
      },
      secretParams: { cookieStr: '', headers: {}, paramValues: {} },
      context: { [ZK_FETCH_CLAIM_CONTEXT_KEY]: digest },
      ownerPrivateKey: `0x${randomBytes(32).toString('hex')}`,
      client: { url: WITNESS_URL },
      zkEngine: 'stwo',
      updateProviderParams: async () => ({ params: { body: '' }, secretParams: {} }),
    });
    if (result.error !== undefined) {
      throw new Error(`zkFetch witness error: ${result.error.message}`);
    }
    if (result.claim === undefined || result.signatures === undefined) {
      throw new Error('zkFetch witness returned no signed claim');
    }

    const signedParameters = JSON.parse(result.claim.parameters) as {
      body?: string;
      method?: string;
      url?: string;
    };
    expect(signedParameters.body).toBe('');
    expect(signedParameters.method).toBe('POST');
    expect(signedParameters.url).toBe(PROBE_URL);

    const signedContext = JSON.parse(result.claim.context) as {
      extractedParameters?: Record<string, string>;
    };
    expect(signedContext.extractedParameters?.q).toBe(String(PAYLOAD.q));

    const evidence: ZkFetchEvidence = {
      claim: result.claim,
      signatureHex: `0x${Buffer.from(result.signatures.claimSignature).toString('hex')}`,
      attestorAddress: result.signatures.attestorAddress.toLowerCase(),
    };
    const verified = await verifyZkFetchProof(evidence);
    const derived = deriveClaimFromEvidence({
      verified,
      policy,
      appId: APP_ID,
      holder: HOLDER,
      valueSlots: 1,
      windowStart,
      windowEnd,
    });
    expect(derived.present).toEqual([true]);
    expect(derived.values).toEqual([BigInt(PAYLOAD.q)]);

    const signedSubject = zkFetchSubjectHashOf(signedRequest);
    const sentSubject = zkFetchSubjectHashOf({ method: 'POST', url: PROBE_URL, body: SENT_BODY });
    expect(hex(derived.subjectHash)).toBe(hex(signedSubject));
    expect(hex(derived.subjectHash)).not.toBe(hex(sentSubject));

    expect(() => assertEvidenceMatchesPolicy(verified, policy)).toThrow(/body/i);

    const witnessAddress = process.env.WITNESS_ADDRESS ?? (await witnessAddressOf(WITNESS_URL));
    const attestor = zkFetchAttestor({
      id: 'probe',
      keyPair: {
        publicKey: 'probe',
        signer: { sign: (message: FlatMessage): string => `sig:${message.join(',')}` },
      },
      witnessAddress,
    });
    await expect(attestor.attest({ policy, evidence, claim: derived })).rejects.toThrow(/body/i);
  }, 180_000);
});
