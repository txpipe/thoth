# Deploying a zkFetch attestor

How to run the attestor side of the zkFetch kind: build an instance, give it
the address of your Reclaim witness, and run that witness. The
[package README](../README.md) explains the terms; the
[dApp guide](dapp-integration.md) covers the other side.

## Building an instance

An attestor instance is a signing key pair and the public address of the
Reclaim witness you run. `@thoth/attestor`'s `AttestorSigner` holds the key;
nothing in this package reads a private key.

```ts
import { zkFetchAttestor } from '@thoth/zk-tls/attestor';

const attestor = zkFetchAttestor({
  id: 'zkFetch-strava-1',
  keyPair, // the attestor's signing key, not the witness's
  witnessAddress: '0x…', // the public address of your Reclaim witness
});
```

Serve `attestor.attest(input)` to dApps over the transport you choose;
`@thoth/client` shows a minimal HTTP one. Share `descriptorOf(attestor)` from
`@thoth/attestor` with the dApps that pin you.

The instance takes no registry slot and no slot counts, so one instance
serves any dApp ([why](https://github.com/txpipe-shop/thoth/tree/main/packages/attestor#design-decisions)).
Each claim proposal carries the slot counts of the contract it is for, up to
your [input limits](#input-limits).

### Input limits

The instance rejects a request larger than its limits while parsing it,
before it checks the proof or signs. `ZK_FETCH_DEFAULT_LIMITS` holds the
defaults ([the list](../README.md#guarantees-and-limits)). Override any of
them with `limits`; the rest keep their defaults:

```ts
const attestor = zkFetchAttestor({
  id: 'zkFetch-strava-1',
  keyPair,
  witnessAddress: '0x…',
  limits: { valueSlots: 128, responseTextLength: 8 * 1024 * 1024 },
});
```

Raise a limit when a dApp you serve needs more slots or a bigger response,
and lower one to fit your machine. A limit only refuses input; it never
changes what you sign. Tell the dApps that pin you what your limits are: an
attestor that refuses a request does not count toward the threshold.
`zkFetchAttestor` throws on an unknown key or a value that is not a positive
integer.

### The witness address

`witnessAddress` is the public Ethereum address of your own Reclaim witness.
The definition's `verify` compares it case-insensitively and rejects evidence
any other witness signed, so an attestor built with `buildAttestor` and
`createZkFetchDefinition({ witnessAddress })` checks the witness too. The attestor
process never receives or derives the witness private key; read the address from the witness's `/address` endpoint:

```bash
curl --fail http://localhost:8001/address
```

Copy the response's `address` field into `witnessAddress`. The local startup
script below prints it too, and `cast wallet address --private-key …` on the
witness host gives the same address.

## The attest flow

The dApp sends the raw input over the transport. The attestor parses it with
its own schemas, requires every policy slot to fit the proposal's slot counts,
and runs the checks of `createZkFetchDefinition({ witnessAddress })`'s `verify`
before signing:

1. The evidence's `attestorAddress` must be your `witnessAddress`, compared
   case-insensitively. This runs before the proof check, so evidence from any
   other witness costs no signature verification.
2. `verifyZkFetchProof(evidence)` verifies the witness's ECDSA signature over
   the claim, checks the claim identifier against its signed content, and reads
   the values the witness disclosed.
3. `assertEvidenceMatchesPolicy(verified, policy)` refuses a signed url, body,
   `geoLocation` or `proxySessionId` that carries a `{{param}}` template, and a
   signed URL that contains `*` or whose host parses to one (see
   [Building the request](dapp-integration.md#building-the-request)), checks
   the attested URL against the host allowlist, checks the signed request body
   against the policy's required [body policy](dapp-integration.md#body-policy),
   requires the witness-signed `responseMatches` and `responseRedactions` to
   equal the policy's canonical disclosure rules, and requires every required
   slot to be certifiable. `responseText` is not witness-signed, so no check
   reads it.
4. `assertObservationInWindow({ claim, verified })` requires the witness's
   observation time to fall inside the proposed window, bounds included. The
   contract bounds the window's length and checks it against block time.
5. `assertClaimMatchesSubject({ claim, verified })` requires the proposal's
   `subjectHash` to be the hash of the request the witness signed.
6. `assertClaimMatchesContext({ claim, verified, policy })` requires the
   context the witness signed to carry the
   [claim context](../../../CONTEXT.md#the-claim) digest of the policy, the
   signed request's subject, and the proposal's holder and window
   ([ADR 0011](../../../docs/adr/0011-evidence-binds-the-claim-context.md)),
   and the proposal's salt to be that digest.
7. `assertClaimMatchesDisclosures({ claim, disclosures, policy })` requires the
   proposal to say exactly what the evidence disclosed.

`attestor.attest` then derives its own claim from the evidence and signs
that: the values and `present` flags from the disclosed values, the signed
request's subject hash, the policy's hash, and the salt from the signed claim
context digest ([ADR 0012](../../../docs/adr/0012-nullifier-hashes-a-secret-attestor-derived-salt.md)).
It takes `appId`, the window and the holder commitment from the proposal, the
last two checked against the digest the witness signed. A client cannot make
you certify a reading the evidence does not support.

## Running a Reclaim witness

Self-host a witness from the
[`attestor-core`](https://github.com/reclaimprotocol/attestor-core) repo:

```bash
git clone --depth 1 https://github.com/reclaimprotocol/attestor-core
cd attestor-core
npm install --ignore-scripts --include=dev
npm rebuild re2 --ignore-scripts=false
node -e "require('re2')" &&
  PRIVATE_KEY=0x… DISABLE_BGP_CHECKS=1 npm run start
```

The witness listens on `ws://localhost:8001/ws`.

- The witness needs the native `re2` module. It compiles your policy's regexes
  with `re2`. If `re2` doesn't load, it falls back to JavaScript `RegExp` and
  only logs a `Failed to load RE2` warning. The `require('re2')` check before
  `npm run start` stops the start instead.
- `--ignore-scripts` skips every install script, including the witness's own
  build. The witness runs from source, so the only script it needs is
  `re2`'s.
- `npm rebuild re2 --ignore-scripts=false` runs that one script, even when
  your npm config sets `ignore-scripts`. It downloads a prebuilt `re2` binary.
  If none matches your platform, it builds one with `node-gyp`.
- Upstream's lockfile marks `re2` as a dev dependency. `--include=dev` keeps it
  when `NODE_ENV=production` or `--omit=dev` would leave it out.
- `PRIVATE_KEY` is the witness's secp256k1 key. Keep it on the witness host
  and give the attestor only the address, as above.
- `AUTHENTICATION_PUBLIC_KEY`, the matching compressed public key, makes the
  witness require a signed `authRequest` from each prover. The signing key
  stays on your backend; a browser fetches a pre-signed request from it.
- Locally the endpoint is plain `ws://`. In production, terminate TLS (`wss://`)
  at a reverse proxy.

For two witnesses at once, run `npm run witnesses --workspace=packages/zk-tls`.
It runs `scripts/start-witnesses.sh`, which clones `attestor-core` at a pinned
commit: `f451eb3`, the source of the 5.1.6 release `@thoth/zk-tls` depends on.
The script installs the clone as above and starts two witnesses on ports 8001
and 8002. It stops with an error if `re2` doesn't load or a port is already in
use. It also stops if a witness logs `Failed to load RE2` or exits. Once both
witnesses answer, it prints each one's address. `WITNESS_REF`,
`WITNESS_CLONE_DIR`, `WITNESS_PORT_A`/`B` and `WITNESS_KEY_A`/`B` override the
defaults. Ctrl-C stops both witnesses.

The npm package ships no witness server, so the script pins a commit by hand.
When Dependabot bumps `@reclaimprotocol/attestor-core`, `witness-pin.test.ts`
fails until you set `PINNED_VERSION` and `PINNED_REF` in the script to the
matching release and run the live check against it.

## Witness agreement and upgrades

Every operator in one trusted set must run the same witness version and
behavior, with `re2` loaded. Witnesses agree only when they add identical context fields to the
Reclaim claim identifier for the same request and disclosures. Thoth does not
pin witness behavior, so an upstream change can split a trusted set: the
client fails closed, `proveReq` with `witnesses disagree` before any attestor
is contacted, and `collect` with `ZkFetchThresholdError` once no message can
reach the threshold.

Before a trusted set adopts a new witness version, coordinate every operator,
run the live check below against the candidate witnesses, and rotate only
after it passes.

## Live check

The live check proves one request with two real witnesses and asserts that
both derive the same identifier and message. It needs network and witness
processes, so `test/live.test.ts` skips unless `WITNESS_URLS` names at least
two witnesses; `npm test` runs it only when that variable is set.

Start two witnesses in one shell:

```bash
npm run witnesses --workspace=packages/zk-tls
```

Run the check in another:

```bash
WITNESS_URLS=ws://localhost:8001/ws,ws://localhost:8002/ws \
  npx vitest run packages/zk-tls/test/live.test.ts
```

The test fetches `https://api.github.com/repos/txpipe/dolos` (`LIVE_URL`
overrides it), reveals only `stargazers_count` and `full_name`, and derives one
numeric-only claim and one claim with a byte slot. For each it checks that both
witnesses derive the same identifier and message, with the star count present
and the byte slot equal to the zero-padded UTF-8 of `full_name`.

`test/empty-body.test.ts` has a second live check, which needs one witness. It
sends a body while the witness signs an empty one, and asserts that a
`non-empty` [body policy](dapp-integration.md#body-policy) refuses the
evidence:

```bash
WITNESS_URLS=ws://localhost:8001/ws \
  npx vitest run packages/zk-tls/test/empty-body.test.ts
```

It posts to `https://httpbin.org/post`; `PROBE_URL` overrides it with any
endpoint that accepts a POST and echoes the JSON body, so the `"q"` match
extracts the digits. Its offline half, which runs Reclaim's receipt check on a
hand-built transcript, always runs.
