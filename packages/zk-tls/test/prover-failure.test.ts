// How `zkFetchProver` classifies Reclaim's failures into `ZkFetchProverError`
// reasons. Most cases run attestor-core's real client against a fake witness
// and a local HTTPS source; the rest stub `createClaimOnAttestor`.
import { createServer } from 'node:net';
import type * as AttestorCore from '@reclaimprotocol/attestor-core';
import { ZkFetchProverError, type ZkFetchRequest } from '@txpipe/thoth-zk-tls/client';
import { type ZkFetchProverConfig, zkFetchProver } from '@txpipe/thoth-zk-tls/prover';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { startFakeWitness, startSource, type TestServer } from './helpers/fake-witness.js';

type CreateClaim = typeof AttestorCore.createClaimOnAttestor;

const stub = vi.hoisted(() => ({
  /** A stand-in for `createClaimOnAttestor`; unset runs the real one. */
  createClaim: undefined as CreateClaim | undefined,
  /** Skip certificate verification, for the self-signed local source. */
  insecure: false,
}));

vi.mock('@reclaimprotocol/attestor-core', async (importOriginal) => {
  const real = await importOriginal<typeof AttestorCore>();
  const createClaimOnAttestor: CreateClaim = (options) => {
    if (stub.createClaim !== undefined) {
      return stub.createClaim(options);
    }
    const params = stub.insecure
      ? { ...options.params, additionalClientOptions: { verifyServerCertificate: false } }
      : options.params;
    return real.createClaimOnAttestor({ ...options, params } as typeof options);
  };
  return { ...real, createClaimOnAttestor };
});

const core = await import('@reclaimprotocol/attestor-core');

const servers: TestServer[] = [];

afterEach(async () => {
  stub.createClaim = undefined;
  stub.insecure = false;
  await Promise.all(servers.splice(0).map((server) => server.close()));
});

const PRICE_MATCH = { type: 'regex' as const, value: '"price":(?<price>\\d+)' };

/** Text that only a remote error carries, so a test can check it never surfaces. */
const REMOTE_TEXT = 'remote-detail-7f3a';

/** A local port with nothing listening on it. */
const closedPort = async (): Promise<number> => {
  const server = createServer();
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  await new Promise((resolve) => server.close(resolve));
  if (address === null || typeof address === 'string') {
    throw new Error('no port');
  }
  return address.port;
};

/** A fake witness and a source answering `body`, both closed after the test. */
const witnessAndSource = async (body = '{"other":1}') => {
  const witness = await startFakeWitness();
  const source = await startSource(body);
  servers.push(witness, source);
  return { witnessUrl: witness.url, url: `https://localhost:${source.port}/price` };
};

/** Prove `request` and return what the prover threw. */
const proveError = async (
  request: ZkFetchRequest,
  config: ZkFetchProverConfig = { witnessUrl: 'ws://localhost:1/ws' },
): Promise<unknown> =>
  zkFetchProver(config)
    .prove(request)
    .then(
      () => {
        throw new Error('prove unexpectedly succeeded');
      },
      (error: unknown) => error,
    );

/** Stub `createClaimOnAttestor` to report `steps`, then throw `error`. */
const failAfter = (steps: readonly AttestorCore.ProofGenerationStep['name'][], error: unknown) => {
  stub.createClaim = async ({ onStep }) => {
    for (const name of steps) {
      onStep?.({ name } as AttestorCore.ProofGenerationStep);
    }
    throw error;
  };
};

/** Assert a classified error with `reason` whose message carries no remote text. */
const expectReason = (error: unknown, reason: ZkFetchProverError['reason']) => {
  expect(error).toBeInstanceOf(ZkFetchProverError);
  expect(error).toMatchObject({ reason });
  expect((error as Error).message).not.toContain(REMOTE_TEXT);
};

/** Assert an error the prover left unclassified, which `collect` reports as `evidence`. */
const expectUnclassified = (error: unknown) => {
  expect(error).toBeInstanceOf(Error);
  expect(error).not.toBeInstanceOf(ZkFetchProverError);
};

describe('zkFetchProver failure reasons, through the real Reclaim client', () => {
  it('reports an unreachable witness as transport', async () => {
    const witnessUrl = `ws://127.0.0.1:${await closedPort()}/ws`;
    const error = await proveError({ url: 'https://localhost/price' }, { witnessUrl });
    expectReason(error, 'transport');
    expect((error as Error).cause).toMatchObject({ code: 'ERROR_NETWORK_ERROR' });
  });

  it('reports a source the witness cannot reach as transport', async () => {
    const witness = await startFakeWitness();
    servers.push(witness);
    const url = `https://localhost:${await closedPort()}/price`;
    const error = await proveError({ url }, { witnessUrl: witness.url });
    expectReason(error, 'transport');
    expect((error as Error).cause).toMatchObject({ code: 'ERROR_INTERNAL' });
  });

  it('reports a source certificate that does not verify as transport', async () => {
    const { witnessUrl, url } = await witnessAndSource();
    const error = await proveError({ url }, { witnessUrl });
    expectReason(error, 'transport');
    expect((error as Error).cause).toMatchObject({
      message: expect.stringMatching(/^Missing issuer/),
    });
  });

  it.each([
    { rule: 'regex', redaction: { regex: '"price":\\d+' } },
    { rule: 'jsonPath', redaction: { jsonPath: '$.price' } },
  ])('reports a $rule redaction that finds nothing as no-match', async ({ redaction }) => {
    stub.insecure = true;
    const { witnessUrl, url } = await witnessAndSource();
    const request = { url, responseMatches: [PRICE_MATCH], responseRedactions: [redaction] };
    expectReason(await proveError(request, { witnessUrl }), 'no-match');
  });

  it('reports a response that fails responseMatches as no-match', async () => {
    stub.insecure = true;
    const { witnessUrl, url } = await witnessAndSource();
    const request = { url, responseMatches: [PRICE_MATCH], responseRedactions: [] };
    const error = await proveError(request, { witnessUrl });
    expectReason(error, 'no-match');
    expect((error as Error).cause).toMatchObject({
      message: expect.stringMatching(/^Invalid receipt\. /),
    });
  });

  it('leaves an unfilled body template unclassified', async () => {
    stub.insecure = true;
    const { witnessUrl, url } = await witnessAndSource();
    const request = { url, method: 'POST' as const, body: '{"q":"{{id}}"}' };
    expectUnclassified(await proveError(request, { witnessUrl }));
  });

  it('leaves a rejecting authRequest unclassified', async () => {
    const { witnessUrl, url } = await witnessAndSource();
    const signerOffline = new Error('signer offline');
    const authRequest = async () => {
      throw signerOffline;
    };
    expect(await proveError({ url }, { witnessUrl, authRequest })).toBe(signerOffline);
  });
});

describe('zkFetchProver failure reasons, from a stubbed Reclaim client', () => {
  it.each([
    'ERROR_NETWORK_ERROR',
    'ERROR_TIMEOUT',
    'ERROR_CERTIFICATE_FETCH_FAILED',
    'ERROR_PROXY_ERROR',
  ] as const)('reports a thrown %s as transport', async (code) => {
    failAfter(['connecting'], new core.AttestorError(code, REMOTE_TEXT));
    expectReason(await proveError({ url: 'https://localhost/price' }), 'transport');
  });

  it.each([
    { code: 'ERROR_INVALID_CLAIM', steps: ['connecting', 'waiting-for-verification'] },
    { code: 'ERROR_AUTHENTICATION_FAILED', steps: ['connecting'] },
    { code: 'ERROR_INTERNAL', steps: ['connecting', 'waiting-for-verification'] },
  ] as const)('leaves a thrown $code after $steps unclassified', async ({ code, steps }) => {
    const thrown = new core.AttestorError(code, REMOTE_TEXT);
    failAfter(steps, thrown);
    expect(await proveError({ url: 'https://localhost/price' })).toBe(thrown);
  });

  it('leaves a claim the witness refuses unclassified, even with malformed data', async () => {
    // The witness's `claimTunnel` handler returns a refusal in `error` as
    // `ERROR_INVALID_CLAIM`; the client decodes it from the wire.
    const { ClaimTunnelResponse, ErrorCode } = core.proto;
    const response = ClaimTunnelResponse.create({
      error: { code: ErrorCode.ERROR_INVALID_CLAIM, message: REMOTE_TEXT, data: '{not json' },
    });
    const refusal = ClaimTunnelResponse.decode(ClaimTunnelResponse.encode(response).finish());
    stub.createClaim = async () => refusal;
    expectUnclassified(await proveError({ url: 'https://localhost/price' }));
  });
});
