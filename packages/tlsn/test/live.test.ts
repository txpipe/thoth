// End to end against real TLSNotary sessions: a local HTTPS server, two notaries run by
// the thoth-tlsn binary, two attestors that each pin one notary, and the client
// collecting a 2-of-2 claim. Skips unless THOTH_TLSN_BIN names a built binary
// (`npm run build:native --workspace=packages/tlsn`).

import { type ChildProcess, spawn } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { createServer, type Server } from 'node:https';
import type { AddressInfo } from 'node:net';
import { dirname, join } from 'node:path';
import { createInterface } from 'node:readline';
import { fileURLToPath } from 'node:url';
import { descriptorOf } from '@txpipe/thoth-attestor';
import { type AttestorTransport, buildTrustedSet } from '@txpipe/thoth-client';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { tlsnAttestor } from '../src/attestor/index.js';
import { tlsnClient } from '../src/client/index.js';
import type { TlsnDefinition, TlsnNotaryKey, TlsnPolicy } from '../src/index.js';
import { nativeProver } from '../src/prover/index.js';
import { nativePresentationVerifier } from '../src/verifier/index.js';
import {
  APP_ID,
  type FakePublicKey,
  type FakeSignature,
  fakeKey,
  fakeSignatureVerifier,
  HOLDER,
} from './helpers.js';

const binary = process.env.THOTH_TLSN_BIN;
const fixtures = join(dirname(fileURLToPath(import.meta.url)), 'fixtures');
const rootCert = join(fixtures, 'root_ca.der');
const SERVER_NAME = 'test-server.thoth';
const BODY = '{"stars":1234,"big":18446744073709551615,"owner":{"login":"octocat"}}';

const POLICY: TlsnPolicy = {
  allowedHosts: [SERVER_NAME],
  hiddenHeaders: ['authorization'],
  slots: [
    { slot: 0, path: ['stars'], parse: 'int' },
    { slot: 1, path: ['big'], parse: 'int' },
    { slot: 2, path: ['owner', 'login'], parse: 'bytes' },
  ],
  bodyPolicy: 'empty',
};

/** Start a notary on a free port and wait for the address and key it prints. */
const startNotary = (signingKey: string) =>
  new Promise<{ child: ChildProcess; address: string; key: TlsnNotaryKey }>((resolve, reject) => {
    const child = spawn(
      binary as string,
      ['notary', '--listen', '127.0.0.1:0', '--root-cert', rootCert],
      {
        env: { ...process.env, THOTH_TLSN_NOTARY_KEY: signingKey },
        stdio: ['ignore', 'pipe', 'inherit'],
      },
    );
    child.on('error', reject);
    createInterface({ input: child.stdout as NodeJS.ReadableStream }).once('line', (line) => {
      const ready = JSON.parse(line) as { listening: string; notaryKey: TlsnNotaryKey };
      resolve({ child, address: ready.listening, key: ready.notaryKey });
    });
  });

describe.skipIf(binary === undefined)('tlsn@1 live, 2-of-2 over real notaries', () => {
  let server: Server;
  let serverPort: number;
  let seenAuthorization: string | undefined;
  const notaries: Awaited<ReturnType<typeof startNotary>>[] = [];

  beforeAll(async () => {
    server = createServer(
      {
        key: readFileSync(join(fixtures, 'server.key')),
        cert: readFileSync(join(fixtures, 'server.crt')),
        // TLSNotary speaks TLS 1.2 with ECDHE over P-256 only.
        maxVersion: 'TLSv1.2',
        ecdhCurve: 'prime256v1',
      },
      (request, response) => {
        seenAuthorization = request.headers.authorization;
        response.writeHead(200, {
          'content-type': 'application/json',
          'content-length': Buffer.byteLength(BODY),
        });
        response.end(BODY);
      },
    );
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    serverPort = (server.address() as AddressInfo).port;
    notaries.push(await startNotary('11'.repeat(32)), await startNotary('22'.repeat(32)));
  });

  afterAll(() => {
    for (const notary of notaries) notary.child.kill();
    server?.close();
  });

  const setup = (proverNotaries: readonly number[]) => {
    const verifier = nativePresentationVerifier({ binary: binary as string, rootCert });
    const attestors = notaries.map((notary, index) =>
      tlsnAttestor({
        id: `tlsn-${index}`,
        keyPair: fakeKey(`tlsn-${index}`),
        notaryKey: notary.key,
        verifier,
      }),
    );
    const trusted = buildTrustedSet({
      registrySize: 2,
      attestors: attestors.map((attestor, registryIndex) => ({
        attestor: descriptorOf(attestor),
        registryIndex,
      })),
    });
    const transport: AttestorTransport<TlsnDefinition, FakePublicKey, FakeSignature> = {
      request: (descriptor, input) => {
        const attestor = attestors.find(({ id }) => id === descriptor.id);
        if (attestor === undefined) throw new Error('unknown attestor');
        return attestor.attest(input);
      },
    };
    const provers = Object.fromEntries(
      attestors.map((attestor, index) => [
        attestor.id,
        nativeProver({
          binary: binary as string,
          notary: (notaries[proverNotaries[index] as number] as (typeof notaries)[number]).address,
          connect: `127.0.0.1:${serverPort}`,
          rootCert,
        }),
      ]),
    );
    return tlsnClient.init({
      trusted,
      transport,
      verifier: fakeSignatureVerifier,
      presentationVerifier: verifier,
      policy: POLICY,
      appId: APP_ID,
      valueSlots: 2,
      byteSlots: 1,
      provers,
    });
  };

  const request = {
    url: `https://${SERVER_NAME}/repos/x?y=1`,
    secretHeaders: { Authorization: 'Bearer s3cret' },
  };
  const now = () => BigInt(Math.floor(Date.now() / 1000));

  it('collects one claim signed by both attestors, each over its own notary session', async () => {
    const client = setup([0, 1]);
    const attestment = await client.collect(request, {
      holder: HOLDER,
      windowStart: now() - 60n,
      windowEnd: now() + 300n,
      threshold: 2,
    });
    expect(attestment.collected.map(({ registryIndex }) => registryIndex)).toEqual([0, 1]);
    expect(attestment.claim.values).toEqual([1234n, 18446744073709551615n]);
    expect(attestment.claim.present).toEqual([true, true, true]);
    // The server saw the secret; the attestors only saw its length.
    expect(seenAuthorization).toBe('Bearer s3cret');
  }, 120_000);

  it('refuses a presentation from a notary the attestor does not pin', async () => {
    // Both provers use notary 0, so attestor 1 sees a key it does not pin.
    const client = setup([0, 0]);
    await expect(
      client.collect(request, {
        holder: HOLDER,
        windowStart: now() - 60n,
        windowEnd: now() + 300n,
        threshold: 2,
      }),
    ).rejects.toMatchObject({
      reason: 'threshold',
      failures: [{ registryIndex: 1, reason: 'attestation' }],
    });
  }, 120_000);
});
