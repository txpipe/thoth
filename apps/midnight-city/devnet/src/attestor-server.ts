// One zkFetch attestor as its own process: it holds a Jubjub key and trusts one witness.
// `GET /descriptor` gives the public key a Bounty pins at deploy; `POST /attest` signs a
// claim when the evidence its witness signed supports it. Its key stays in this process.
// Usage: npm run attestor -- <id> <port> <witness address>
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { join } from 'node:path';
import {
  CompactTypeField,
  CompactTypeVector,
  jubjubSchnorrSign,
  jubjubSchnorrVerifyingKey,
  sampleJubjubSchnorrSk,
} from '@midnight-ntwrk/compact-runtime';
import { zkFetchAttestor } from '@thoth/zk-tls/attestor';
import { decode, encode } from './wire.js';

const [id, port, witnessAddress] = process.argv.slice(2);
if (id === undefined || port === undefined || witnessAddress === undefined) {
  throw new Error('usage: npm run attestor -- <id> <port> <witness address>');
}

// The key lives with the devnet's state, so a fresh chain gets fresh attestors.
const keyDir = join(import.meta.dirname, '../.state/attestors');
const keyFile = join(keyDir, `${id}.key`);
if (!existsSync(keyFile)) {
  mkdirSync(keyDir, { recursive: true, mode: 0o700 });
  writeFileSync(keyFile, sampleJubjubSchnorrSk().toString(16), { mode: 0o600 });
}
const sk = BigInt(`0x${readFileSync(keyFile, 'utf8').trim()}`);
const publicKey = jubjubSchnorrVerifyingKey(sk);

const attestor = zkFetchAttestor({
  id,
  keyPair: {
    publicKey,
    signer: {
      sign: (message) =>
        jubjubSchnorrSign(
          new CompactTypeVector(message.length, CompactTypeField),
          [...message],
          sk,
        ),
    },
  },
  witnessAddress,
});

const readBody = async (request: AsyncIterable<Buffer>): Promise<string> => {
  const chunks: Buffer[] = [];
  for await (const chunk of request) {
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString('utf8');
};

createServer(async (request, response) => {
  const reply = (status: number, body: unknown): void => {
    response.writeHead(status, { 'content-type': 'application/json' }).end(encode(body));
  };
  try {
    if (request.method === 'GET' && request.url === '/descriptor') {
      reply(200, { id, publicKey, witnessAddress });
    } else if (request.method === 'POST' && request.url === '/attest') {
      const input = decode(await readBody(request)) as Parameters<typeof attestor.attest>[0];
      reply(200, await attestor.attest(input));
      console.log(`${new Date().toISOString()} ${id}: signed`);
    } else {
      reply(404, { error: 'not found' });
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.log(`${new Date().toISOString()} ${id}: refused (${message})`);
    reply(400, { error: message });
  }
}).listen(Number(port), '127.0.0.1', () => {
  console.log(`attestor ${id} on :${port}, trusting witness ${witnessAddress}`);
});
