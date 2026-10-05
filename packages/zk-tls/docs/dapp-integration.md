# @thoth/zk-tls dApp integration

Using the zkFetch kind from a dApp: configure the client, build requests and
policies, hand the attestation to the contract, and drive a Reclaim witness.
See the [package README](../README.md) for what the package exports and
[attestor-guide.md](attestor-guide.md) for the attestor host side.

## Client setup

Seven things go into `zkFetchClient.init`:

- **`trusted`.** The attestors your app pins, assembled with `@thoth/client`'s
  `buildTrustedSet(descriptors)`. A descriptor is `{ id, definition, publicKey,
  registryIndex }`, from your deploy config and the attestor network; see
  `@thoth/client` for the trusted-set rules.
- **`transport`.** How the client reaches each attestor. App-supplied; the
  host-side mirror is `Attestor.attest`, and `@thoth/client` has a minimal HTTP
  example.
- **`verifier`.** The attestor signature verifier. For Jubjub Schnorr, use
  `jubjubVerifier` from `@thoth/client/jubjub`.
- **`policy`.** The law every attestor in the set will check against; see below.
  Every claim carries `zkFetchPolicyHashOf(policy)` as its `policyHash`, and
  the consuming contract must seal that hash in its `policyHashes` set at
  deploy, or it rejects the claim.
- **`appId`.** The 32 bytes naming your app, signed into every claim.
- **`valueSlots`.** The value-slot count of the contract that consumes the
  claim, its `#V`.
- **`provers`.** Where evidence comes from, keyed by attestor id. Each entry
  points at that attestor's own witness: `zkFetchProver({ witnessUrl })`, or any
  object with a `prove(request)` method. Every attestor in `trusted` needs an
  entry, and every entry needs an attestor.

A complete setup:

```ts
import { buildTrustedSet, type AttestorTransport } from '@thoth/client';
import { jubjubVerifier } from '@thoth/client/jubjub';
import type { ZkFetchDefinition } from '@thoth/zk-tls';
import { zkFetchClient } from '@thoth/zk-tls/client';
import { zkFetchProver } from '@thoth/zk-tls/prover';

const trusted = buildTrustedSet(descriptors);

const transport: AttestorTransport<ZkFetchDefinition, PublicKey, Signature> = {
  async request(attestor, input) {
    const res = await fetch(`https://${attestor.id}/attest`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(input),
    });
    if (!res.ok) throw new Error(`attestor ${attestor.id} rejected: ${res.status}`);
    return res.json();
  },
};

const policy = zkFetchPolicySchema.parse({
  allowedHosts: ['www.strava.com'],
  slots: [
    { slot: 0, name: 'distance', parse: 'float' },
    { slot: 1, name: 'movingTime', parse: 'int' },
  ],
});

const client = zkFetchClient.init({
  trusted,
  transport,
  verifier: jubjubVerifier,
  policy,
  appId, // 32 bytes
  valueSlots: 2, // the contract's #V
  provers: {
    'attestor-0': zkFetchProver({ witnessUrl: 'ws://localhost:8001/ws' }),
    'attestor-1': zkFetchProver({ witnessUrl: 'ws://localhost:8002/ws' }),
  },
});

// import { holderCommitmentOf } from '@thoth/core/claim-context';
// Generate holderSecret as 32 cryptographically random bytes and retain it locally.
const holder = holderCommitmentOf(holderSecret);
const proof = await client.proveReq({
  url: 'https://www.strava.com/api/v3/athlete/activities?per_page=1',
  method: 'GET',
  publicHeaders: { accept: 'application/json' },
  secretHeaders: { authorization: `Bearer ${accessToken}` },
  responseMatches: [
    { type: 'regex', value: '"distance":\\s*(?<distance>[\\d.]+)' },
    { type: 'regex', value: '"moving_time":\\s*(?<movingTime>\\d+)' },
  ],
  responseRedactions: [
    { regex: '"distance":\\s*[\\d.]+' },
    { regex: '"moving_time":\\s*\\d+' },
  ],
  context: { label: 'strava-activity' },
}, holder);

const attestment = await proof.attest(); // or .attest('attestor-0')
```

## Collecting a threshold

For a resilient one-call flow, use `collect` instead of the proof-handle flow:

```ts
const start = Math.floor(Date.now() / 1000);
const attestment = await client.collect(request, {
  holder,
  windowStart: BigInt(start),
  windowEnd: BigInt(start + 60),
  expiresAt: Date.now() + 60_000,
  threshold: 2,
  operatorTimeoutMs: 20_000,
});
```

Set the window to the consuming contract's permitted freshness and width, and
`threshold` to its on-chain N. Pass an ordered `attestorIds` list to limit which
witnesses' sessions use your secret headers. The result is one agreeing group,
submitted with the registry placement described below; see the
[README](../README.md#threshold-collection) for the failure semantics.

## Building the request

`proveReq(request, holder)` takes a `ZkFetchRequest` and the per-claim commitment
from `holderCommitmentOf`, imported from `@thoth/core/claim-context`. Keep the
secret for the contract witness and use a fresh high-entropy secret per claim.
Reusing it links claims; Thoth makes no cross-claim unlinkability promise.

The request describes the fetch; the witness signs these parameters into
the claim, so the policy can rely on them. Field-by-field docs live in
`ZkFetchRequest`'s JSDoc in `src/client/index.ts`. The two that carry protocol
semantics:

- `responseMatches` selects patterns that get certified. A named group
  (`(?<distance>…)`) becomes a disclosed value keyed by the group name;
  `contains` matches only guard the response. It defaults to `(?<data>.*)`, the
  whole response.
- `responseRedactions` is Reclaim's reveal whitelist. The selected slices are
  the only parts of the response the witness, and therefore the proof, ever
  sees. Everything else stays hidden. Select with `regex`, `jsonPath`, or
  `xPath`.

A policy slot is certifiable only when a `responseMatches` group extracted the
value from a revealed slice; name the slot exactly like the regex group.

Whatever you reveal must be identical across independent fetches, because each
witness signs the revealed slice into the claim's context. A whole-response
`(?<data>.*)` match is not safe: HTTP headers carry per-request values such as
rate limits, dates, and request ids, so two witnesses derive different
identifiers and `proveReq` rejects the set with `witnesses disagree`. Reveal
only the field the policy binds, and prefer values the origin returns
deterministically.

## Witness agreement and upgrades

Every operator in one trusted set must run the same witness version and behavior.
Two witnesses agree only when they add identical context fields to the Reclaim
claim identifier for the same request and disclosures. Thoth does not pin witness
behavior. An upstream witness change can silently split every affected trusted
set; `proveReq` fails closed with `witnesses disagree`, causing an availability
failure before any attestor is contacted.

When a witness version or behavior changes, coordinate all operators and re-run
the [live check](../README.md#live-check) with `WITNESS_URLS` pointing to the
candidate witnesses before rotating the trusted set. Rotate only after the
check confirms that they derive the same identifier and message.

## Building the policy

Every attestor in a trusted set will enforce the same policy. Field docs live in
`zkFetchPolicySchema`'s JSDoc in `src/index.ts`:

`int` accepts only decimal digits and requires a value below `2^64`.
`float` accepts a whole string matching
`[0-9]+(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?`: digits, an optional decimal point
followed by digits, and an optional base-10 exponent. Leading zeros are allowed.
Whitespace, leading signs, grouping separators, trailing junk, `NaN`, and
`Infinity` are rejected. For example, `12abc`, `1,000`, `.5`, and `1.` are invalid;
`0.5` and `2.5e2` are valid.

`float` rounds exactly to the nearest integer, with halves rounded up, and
requires the rounded result to be below `2^64`. It never converts the numeric
value to a JavaScript double: `9007199254740993` stays `9007199254740993`, and
`0.49999999999999999999` rounds to zero. A required slot whose value is missing
or unparseable rejects the evidence; an `optional` slot is signed unpresent.

`responseText`, when present in evidence or prover output, is untrusted,
client-supplied transport output. The witness signature does not authenticate
it. The policy therefore has no response-size bound; `maxResponseBytes` has
been removed. Recompute any policy hash that included that field. Apply
transport size limits separately from attestation policy checks.

## Handing it to the contract

`attestment.claim` is the claim every attestor signed and `attestment.message`
is its flat encoding; each `attestment.collected[i]` carries the `registryIndex`
slot its attestor answered from. Place each signature at its slot in the
contract's fixed signature vector and call `verifyAttestation` with the claim.
See `@thoth/contracts` for the circuit and the registry wiring.

Each attestor operator runs their own Reclaim witness and builds the attestor
with that witness's public address. The dApp points each attestor's prover at
the matching witness URL, so the evidence an attestor receives comes from the one witness it
trusts. See [attestor-guide.md](attestor-guide.md) for running one.

Replay protection uses the signed observation fields, including the window and
disclosed values. Changing caller context or holder does not create a new observation. If the witnesses
disagree on the request, context, or disclosed values, `proveReq` throws before
contacting any attestor.

A genuine committed proof lives at
`../../../examples/demo-attestation/fixtures/fixture-github-repo-stats.json`.
Three numeric fields are disclosed and everything else is hidden.
`../scripts/make-fixture.mjs` regenerates it. It proves against a witness,
Reclaim's cloud one by default or `ATTESTOR_WS_URL` for your own, and
re-verifies the evidence with the attestor's own verifier.

## Reclaim's hosted zkFetch SDK

`@reclaimprotocol/zk-fetch` is a different, higher-level prover. You initialize
its `ReclaimClient` with an **application id and secret** from the Reclaim
Developer Portal, and it manages the parts the direct path leaves to you:
application credentials, witness discovery (you never choose a witness;
the finished proof carries the `witnesses[].url` it used), and a retry/geolocation layer.

Adapt the hosted client's output with the canonicalizer by wrapping a `ReclaimClient` with our `ZkFetchProver`:

```ts
import { ReclaimClient } from '@reclaimprotocol/zk-fetch';
import { toCanonicalEvidence, type ZkFetchProver } from '@thoth/zk-tls/client';

const hostedProver = (client: ReclaimClient): ZkFetchProver => ({
  prove: async (request) =>
    toCanonicalEvidence(
      await client.zkFetch(
        request.url,
        { method: request.method, headers: request.publicHeaders, context: request.context },
        {
          headers: request.secretHeaders,
          responseMatches: request.responseMatches,
          responseRedactions: request.responseRedactions,
        },
      ),
    ),
});
```

`@reclaimprotocol/zk-fetch` is AGPL-licensed and this package does not depend
on it.

This path lets Reclaim choose the witness per call, so it only fits a trusted
set whose attestors all pin that witness address. A set of operators running their
own witnesses needs one direct `zkFetchProver` per attestor instead.

References:

- [@reclaimprotocol/zk-fetch README](https://github.com/reclaimprotocol/zk-fetch)
  — `ReclaimClient` init, credential modes, `useTee`, `zkEngine`,
  `geoLocation`, and the `witnesses[].url` in the proof output.
- [Reclaim Developer Portal](https://dev.reclaimprotocol.org/) — application
  id and secret for the hosted client.
- [make-fixture.mjs](../scripts/make-fixture.mjs) — the
  default `wss://attestor.reclaimprotocol.org:444/ws` cloud witness URL the
  direct `zkFetchProver` path targets.