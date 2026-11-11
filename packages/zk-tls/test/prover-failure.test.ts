// How `zkFetchProver` classifies Reclaim's failures into `ZkFetchProverError`
// reasons. The receipt errors come from attestor-core's own HTTP provider.
import { createServer } from 'node:net';
import type * as AttestorCore from '@reclaimprotocol/attestor-core';
import { ZkFetchProverError, type ZkFetchRequest } from '@thoth/zk-tls/client';
import { zkFetchProver } from '@thoth/zk-tls/prover';
import { afterEach, describe, expect, it, vi } from 'vitest';

type CreateClaim = typeof AttestorCore.createClaimOnAttestor;

/** A stand-in for `createClaimOnAttestor`; unset runs the real one. */
const stub = vi.hoisted(() => ({ createClaim: undefined as CreateClaim | undefined }));

vi.mock('@reclaimprotocol/attestor-core', async (importOriginal) => {
  const real = await importOriginal<typeof AttestorCore>();
  const createClaimOnAttestor: CreateClaim = (options) =>
    (stub.createClaim ?? real.createClaimOnAttestor)(options);
  return { ...real, createClaimOnAttestor };
});

const core = await import('@reclaimprotocol/attestor-core');

afterEach(() => {
  stub.createClaim = undefined;
});

const REQUEST: ZkFetchRequest = {
  url: 'https://example.com/price',
  responseMatches: [{ type: 'regex', value: '"price":(?<price>\\d+)' }],
  responseRedactions: [{ regex: '"price":\\d+' }],
};

/** Text that only a remote error carries, so a test can check it never surfaces. */
const REMOTE_TEXT = 'remote-detail-7f3a';

const silent = {
  trace: () => undefined,
  debug: () => undefined,
  info: () => undefined,
  warn: () => undefined,
  error: () => undefined,
  child: () => silent,
} as unknown as AttestorCore.Logger;

/** The error attestor-core's HTTP provider throws when the response fails `responseMatches`. */
const receiptNoMatch = async (): Promise<Error> => {
  const params = {
    url: REQUEST.url,
    method: 'GET' as const,
    responseMatches: [...(REQUEST.responseMatches ?? [])],
    responseRedactions: [],
    body: '',
    paramValues: {},
  };
  const secretParams = { cookieStr: '', headers: {}, paramValues: {} };
  const { data } = core.providers.http.createRequest(secretParams, params, silent);
  const request = typeof data === 'string' ? new TextEncoder().encode(data) : data;
  const response = new TextEncoder().encode(
    'HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\n{"price":"n"}',
  );
  const version = core.DEFAULT_METADATA.clientVersion;
  try {
    await core.providers.http.assertValidProviderReceipt({
      clientVersion: version,
      receipt: [
        { sender: 'client', message: request },
        { sender: 'server', message: response },
      ],
      params: { ...params, secretParams },
      logger: silent,
      ctx: { version },
    });
  } catch (error) {
    return error as Error;
  }
  throw new Error('the receipt unexpectedly matched');
};

/**
 * The response a witness sends for a claim it refuses: its `claimTunnel`
 * handler wraps the error as `ERROR_INVALID_CLAIM` in `error`, and the client
 * decodes it from the wire.
 */
const witnessRefusal = (error: Error): Awaited<ReturnType<CreateClaim>> => {
  const { ClaimTunnelResponse } = core.proto;
  const response = ClaimTunnelResponse.create({
    error: core.AttestorError.fromError(error, 'ERROR_INVALID_CLAIM').toProto(),
  });
  return ClaimTunnelResponse.decode(ClaimTunnelResponse.encode(response).finish());
};

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

/** Prove `REQUEST` and return what the prover threw. */
const proveError = async (witnessUrl = 'ws://localhost:1/ws'): Promise<unknown> =>
  zkFetchProver({ witnessUrl })
    .prove(REQUEST)
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

/** Assert a classified error with `reason` that carries no remote text. */
const expectReason = (error: unknown, reason: ZkFetchProverError['reason']) => {
  expect(error).toBeInstanceOf(ZkFetchProverError);
  expect(error).toMatchObject({ reason });
  expect((error as Error).message).not.toContain(REMOTE_TEXT);
};

describe('zkFetchProver failure reasons', () => {
  it('reports an unreachable witness as transport', async () => {
    const error = await proveError(`ws://127.0.0.1:${await closedPort()}/ws`);
    expectReason(error, 'transport');
    expect((error as Error).cause).toMatchObject({ code: 'ERROR_NETWORK_ERROR' });
  });

  it.each([
    'ERROR_NETWORK_ERROR',
    'ERROR_TIMEOUT',
    'ERROR_CERTIFICATE_FETCH_FAILED',
    'ERROR_PROXY_ERROR',
  ] as const)('reports a thrown %s as transport', async (code) => {
    failAfter(['connecting'], new core.AttestorError(code, REMOTE_TEXT));
    expectReason(await proveError(), 'transport');
  });

  it('reports a TLS failure during connecting as transport', async () => {
    failAfter(['connecting'], new Error(`Certificate is not for host ${REMOTE_TEXT}`));
    expectReason(await proveError(), 'transport');
  });

  it("reports the client's own receipt check as no-match", async () => {
    const local = await receiptNoMatch();
    expect(local).not.toBeInstanceOf(core.AttestorError);
    failAfter(['connecting', 'sending-request-data', 'waiting-for-response'], local);
    const error = await proveError();
    expectReason(error, 'no-match');
    expect((error as Error).cause).toBe(local);
  });

  it('reports a witness that refuses the match as no-match', async () => {
    const refusal = witnessRefusal(await receiptNoMatch());
    expect(refusal.error?.code).toBe(core.proto.ErrorCode.ERROR_INVALID_CLAIM);
    stub.createClaim = async () => refusal;
    const error = await proveError();
    expectReason(error, 'no-match');
    expect((error as Error).message).not.toMatch(/Invalid receipt|didn't match/);
  });

  it('keeps any other Reclaim error unclassified', async () => {
    const auth = new core.AttestorError('ERROR_AUTHENTICATION_FAILED', REMOTE_TEXT);
    failAfter(['connecting'], auth);
    expect(await proveError()).toBe(auth);

    const status = new Error('Provider returned error 404');
    failAfter(['connecting', 'sending-request-data', 'waiting-for-response'], status);
    expect(await proveError()).toBe(status);
  });
});
