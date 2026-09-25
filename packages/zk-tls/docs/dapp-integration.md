# @thoth/zk-tls dApp integration

Using the zkFetch kind from a dApp: configure the client, build requests and
policies, hand the attestation to the contract, and drive a Reclaim witness.
See the [package README](../README.md) for what the package exports and
[attestor-guide.md](attestor-guide.md) for the attestor host side.

## Client setup

Five things go into `zkFetchClient.init`:

- **`trusted`.** The attestors your app pins, assembled with `@thoth/client`'s
  `buildTrustedSet(descriptors)`. A descriptor is `{ id, definition, publicKey,
  registryIndex }`, from your deploy config and the attestor network; see
  `@thoth/client` for the trusted-set rules.
- **`transport`.** How the client reaches each attestor. App-supplied; the
  host-side mirror is `Attestor.attest`, and `@thoth/client` has a minimal HTTP
  example.
- **`policy`.** The law every attestor in the set will check against; see below.
- **`valueSlots`.** The value-slot count of the contract that consumes the
  claim, its `#V`.
- **`provers`.** Where evidence comes from, keyed by attestor id. Each entry
  points at that attestor's own witness: `zkFetchProver({ witnessUrl })`, or any
  object with a `prove(request)` method. Every attestor in `trusted` needs an
  entry, and every entry needs an attestor.

A complete setup:

```ts
import { buildTrustedSet, type AttestorTransport } from '@thoth/client';
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
  policy,
  valueSlots: 2, // the contract's #V
  provers: {
    'attestor-0': zkFetchProver({ witnessUrl: 'ws://localhost:8001/ws' }),
    'attestor-1': zkFetchProver({ witnessUrl: 'ws://localhost:8002/ws' }),
  },
});

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
});

const attestment = await proof.attest(); // or .attest('attestor-0')
```

## Building the request

`proveReq` takes a `ZkFetchRequest`; the witness signs these parameters into
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

## Building the policy

Every attestor in a trusted set will enforce the same policy. Field docs live in
`zkFetchPolicySchema`'s JSDoc in `src/index.ts`:

`int` accepts digits below `2^64`; `float` is rounded to the nearest integer and
must be finite, non-negative, and below `2^64`. A required slot whose value is
missing or unparseable rejects the evidence; an `optional` slot is signed
unpresent.

## Handing it to the contract

`attestment.claim` is the claim every attestor signed and `attestment.message`
is its flat encoding; each `attestment.collected[i]` carries the `registryIndex`
slot its attestor answered from. Place each signature at its slot in the
contract's fixed signature vector and call `verifyAttestation` with the claim.
See `@thoth/contracts` for the circuit and the registry wiring.

Each attestor operator runs their own Reclaim witness and builds the attestor
with that witness's key. The dApp points each attestor's prover at the matching
witness URL, so the evidence an attestor receives comes from the one witness it
trusts. See [attestor-guide.md](attestor-guide.md) for running one.

`proveReq` also signs a fresh random nonce (`thothNonce`) into every witness's
context, so one observation cannot be replayed as another. If the witnesses
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
set whose attestors all pin that witness key. A set of operators running their
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