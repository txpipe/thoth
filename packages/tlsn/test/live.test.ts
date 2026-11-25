// End to end against real TLSNotary sessions: a local HTTPS server, two notaries run by
// the thoth-tlsn binary, two attestors that each pin one notary, and the client collecting
// a 2-of-2 claim under a zkFetch-shaped policy. Skips unless THOTH_TLSN_BIN names a built
// binary (`npm run build:native --workspace=packages/tlsn`).

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
import { type TlsnRequest, tlsnClient, tlsnProver } from '../src/client/index.js';
import {
  type TlsnDefinition,
  type TlsnEvidence,
  type TlsnNotaryKey,
  type TlsnPolicy,
  verifiedPresentationSchema,
} from '../src/index.js';
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
const PRIVATE_EMAIL = 'private@example.com';
const BODY = JSON.stringify({
  login: 'octocat',
  email: PRIVATE_EMAIL,
  stars: 1234,
  plan: { name: 'pro', seats: 7 },
});
const SECRET = 'Bearer s3cret-token';

// The policy a zkFetch dApp would write: reveal two fields, read them with regexes.
const POLICY: TlsnPolicy = {
  allowedHosts: ['thoth'],
  slots: [
    { slot: 0, name: 'stars', parse: 'int' },
    { slot: 1, name: 'login', parse: 'bytes' },
  ],
  responseMatches: [
    { type: 'regex', value: '"stars":(?<stars>\\d+)' },
    { type: 'regex', value: '"login":"(?<login>[^"]+)"' },
  ],
  responseRedactions: [{ jsonPath: '$.stars' }, { jsonPath: '$.login' }],
  bodyPolicy: 'ignored',
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

describe.skipIf(binary === undefined)('tlsn@1 live, zkFetch-shaped, over real notaries', () => {
  let server: Server;
  let serverPort: number;
  let seenAuthorization: string | undefined;
  const notaries: Awaited<ReturnType<typeof startNotary>>[] = [];
  const verifier = () => nativePresentationVerifier({ binary: binary as string, rootCert });

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
        if (request.url === '/chunked') {
          // No Content-Length, so Node frames the body as chunks.
          response.writeHead(200, { 'content-type': 'application/json; charset=utf-8' });
          response.write(BODY.slice(0, 20));
          response.end(BODY.slice(20));
          return;
        }
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

  const provers = (proverNotaries: readonly number[], evidences?: TlsnEvidence[]) =>
    Object.fromEntries(
      proverNotaries.map((notary, index) => {
        const prover = tlsnProver({
          binary: binary as string,
          notary: (notaries[notary] as (typeof notaries)[number]).address,
          connect: `127.0.0.1:${serverPort}`,
          rootCert,
        });
        return [
          `tlsn-${index}`,
          {
            prove: async (request: TlsnRequest) => {
              const evidence = await prover.prove(request);
              evidences?.push(evidence);
              return evidence;
            },
          },
        ];
      }),
    );

  const setup = (proverNotaries: readonly number[], evidences?: TlsnEvidence[]) => {
    const attestors = notaries.map((notary, index) =>
      tlsnAttestor({
        id: `tlsn-${index}`,
        keyPair: fakeKey(`tlsn-${index}`),
        notaryKey: notary.key,
        verifier: verifier(),
      }),
    );
    const transport: AttestorTransport<TlsnDefinition, FakePublicKey, FakeSignature> = {
      request: (descriptor, input) => {
        const attestor = attestors.find(({ id }) => id === descriptor.id);
        if (attestor === undefined) throw new Error('unknown attestor');
        return attestor.attest(input);
      },
    };
    return tlsnClient.init({
      trusted: buildTrustedSet({
        registrySize: 2,
        attestors: attestors.map((attestor, registryIndex) => ({
          attestor: descriptorOf(attestor),
          registryIndex,
        })),
      }),
      transport,
      verifier: fakeSignatureVerifier,
      presentationVerifier: verifier(),
      policy: POLICY,
      appId: APP_ID,
      valueSlots: 1,
      byteSlots: 1,
      provers: provers(proverNotaries, evidences),
    });
  };

  const now = () => BigInt(Math.floor(Date.now() / 1000));
  const options = () => ({
    holder: HOLDER,
    windowStart: now() - 60n,
    windowEnd: now() + 300n,
    threshold: 2,
    expiresAt: Date.now() + 120_000,
    attestorTimeoutMs: 60_000,
  });

  it('collects one claim from the redacted response, and the attestors see only the revealed slices', async () => {
    const evidences: TlsnEvidence[] = [];
    const attestment = await setup([0, 1], evidences).collect(
      {
        url: `https://${SERVER_NAME}/repos/x?y=1`,
        secretHeaders: { Authorization: SECRET },
      },
      options(),
    );
    expect(attestment.collected.map(({ registryIndex }) => registryIndex)).toEqual([0, 1]);
    expect(attestment.failures).toEqual([]);
    expect(attestment.claim.values).toEqual([1234n]);
    expect(
      Buffer.from(attestment.claim.byteValues[0] as Uint8Array)
        .subarray(0, 7)
        .toString(),
    ).toBe('octocat');
    expect(seenAuthorization).toBe(SECRET);

    // What an attestor receives: the email, the plan and the secret never appear.
    expect(evidences).toHaveLength(2);
    for (const evidence of evidences) {
      const view = verifiedPresentationSchema.parse(await verifier().verify(evidence.presentation));
      const visible = (direction: typeof view.received) =>
        Buffer.from(
          direction.data.map((byte, index) =>
            direction.revealed.some(([start, end]) => index >= start && index < end) ? byte : 0x2a,
          ),
        ).toString('latin1');
      const received = visible(view.received);
      expect(received).toContain('"stars":1234');
      expect(received).toContain('"login":"octocat"');
      expect(received).not.toContain(PRIVATE_EMAIL);
      expect(received).not.toContain('pro');
      expect(visible(view.sent)).not.toContain('s3cret');
      expect(visible(view.sent)).toContain('Authorization: ');
    }
  }, 120_000);

  it('reads a chunked response through its revealed framing', async () => {
    const attestment = await setup([0, 1]).collect(
      { url: `https://${SERVER_NAME}/chunked` },
      options(),
    );
    expect(attestment.claim.values).toEqual([1234n]);
  }, 120_000);

  it('reports no-match when a redaction selects nothing', async () => {
    const policy: TlsnPolicy = {
      ...POLICY,
      responseRedactions: [{ jsonPath: '$.missing' }],
    };
    const attestors = notaries.map((notary, index) =>
      tlsnAttestor({
        id: `tlsn-${index}`,
        keyPair: fakeKey(`tlsn-${index}`),
        notaryKey: notary.key,
        verifier: verifier(),
      }),
    );
    const other = tlsnClient.init({
      trusted: buildTrustedSet({
        registrySize: 2,
        attestors: attestors.map((attestor, registryIndex) => ({
          attestor: descriptorOf(attestor),
          registryIndex,
        })),
      }),
      transport: { request: () => Promise.reject(new Error('not reached')) },
      verifier: fakeSignatureVerifier,
      presentationVerifier: verifier(),
      policy,
      appId: APP_ID,
      valueSlots: 1,
      byteSlots: 1,
      provers: provers([0, 1]),
    });
    const error = await other
      .collect({ url: `https://${SERVER_NAME}/repos/x` }, options())
      .catch((caught: unknown) => caught);
    expect(error).toMatchObject({ reason: 'threshold' });
    expect(
      (error as { failures: { reason: string }[] }).failures.map(({ reason }) => reason),
    ).toEqual(['no-match', 'no-match']);
  }, 120_000);

  it('refuses a presentation from a notary the attestor does not pin', async () => {
    // Both provers use notary 0, so attestor 1 sees a key it does not pin.
    await expect(
      setup([0, 0]).collect({ url: `https://${SERVER_NAME}/repos/x` }, options()),
    ).rejects.toMatchObject({
      reason: 'threshold',
      failures: [{ registryIndex: 1, reason: 'attestation' }],
    });
  }, 120_000);
});
