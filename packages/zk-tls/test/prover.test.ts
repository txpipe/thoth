// zkFetchProver's mapping between ZkFetchRequest, Reclaim's createClaimOnAttestor
// and ZkFetchEvidence, against a mocked attestor-core so CI covers it offline.
import { zkFetchEvidenceSchema } from '@thoth/zk-tls';
import { zkFetchProver } from '@thoth/zk-tls/prover';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const createClaimOnAttestor = vi.hoisted(() => vi.fn());
vi.mock('@reclaimprotocol/attestor-core', () => ({ createClaimOnAttestor }));
vi.mock('@reclaimprotocol/tls', () => ({ setCryptoImplementation: vi.fn() }));
vi.mock('@reclaimprotocol/tls/webcrypto', () => ({ webcryptoCrypto: {} }));

const claim = {
  provider: 'http',
  parameters: '{"url":"https://api.github.com/x"}',
  owner: '0x0000000000000000000000000000000000000001',
  timestampS: 1_786_122_944,
  context: JSON.stringify({ extractedParameters: { data: '{"ok":true}' } }),
  identifier: `0x${'11'.repeat(32)}`,
  epoch: 1,
};
const signatures = {
  claimSignature: new Uint8Array(65).fill(0xab),
  attestorAddress: '0xC340FC267CACBB9E3101ADCED0C7728F7E63B63D',
};

const prover = zkFetchProver({ witnessUrl: 'ws://localhost:8001/ws' });

/** The options object `prove` passed to `createClaimOnAttestor`. */
const sentOptions = () => createClaimOnAttestor.mock.calls[0]?.[0];

beforeEach(() => {
  createClaimOnAttestor.mockReset();
  createClaimOnAttestor.mockResolvedValue({ claim, signatures });
});

describe('zkFetchProver', () => {
  it('defaults to GET, an empty body and the whole-response match', async () => {
    await prover.prove({ url: 'https://api.github.com/x' });
    expect(sentOptions()).toMatchObject({
      name: 'http',
      params: {
        url: 'https://api.github.com/x',
        method: 'GET',
        body: '',
        responseMatches: [{ type: 'regex', value: '(?<data>.*)' }],
        responseRedactions: [],
        paramValues: {},
      },
      secretParams: { cookieStr: '', headers: {}, paramValues: {} },
      zkEngine: 'stwo',
      client: { url: 'ws://localhost:8001/ws' },
    });
  });

  it('passes the request through, secret headers only as secret params', async () => {
    await prover.prove({
      url: 'https://api.github.com/x',
      method: 'POST',
      body: '{"q":1}',
      publicHeaders: { accept: 'application/json' },
      secretHeaders: { authorization: 'Bearer s3cret' },
      context: { app: 'demo' },
      responseMatches: [{ type: 'contains', value: 'ok' }],
      responseRedactions: [{ jsonPath: '$.ok' }],
    });
    const options = sentOptions();
    expect(options).toMatchObject({
      params: {
        method: 'POST',
        body: '{"q":1}',
        headers: { accept: 'application/json' },
        responseMatches: [{ type: 'contains', value: 'ok' }],
        responseRedactions: [{ jsonPath: '$.ok' }],
      },
      secretParams: { headers: { authorization: 'Bearer s3cret' } },
      context: { app: 'demo' },
    });
    expect(JSON.stringify(options.params)).not.toContain('s3cret');
  });

  it('maps the signed claim to evidence the evidence schema accepts', async () => {
    const evidence = await prover.prove({ url: 'https://api.github.com/x' });
    expect(evidence).toEqual({
      claim,
      signatureHex: `0x${'ab'.repeat(65)}`,
      attestorAddress: signatures.attestorAddress.toLowerCase(),
      responseText: '{"ok":true}',
    });
    expect(zkFetchEvidenceSchema.parse(evidence)).toEqual(evidence);
  });

  it('throws the witness error', async () => {
    createClaimOnAttestor.mockResolvedValue({ error: { message: 'host not allowed' } });
    await expect(prover.prove({ url: 'https://api.github.com/x' })).rejects.toThrow(
      'zkFetch witness error: host not allowed',
    );
  });

  it('throws when the witness returns no signed claim', async () => {
    createClaimOnAttestor.mockResolvedValue({ claim });
    await expect(prover.prove({ url: 'https://api.github.com/x' })).rejects.toThrow(
      'zkFetch witness returned no signed claim',
    );
  });
});
