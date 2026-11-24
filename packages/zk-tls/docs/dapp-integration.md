# @txpipe/thoth-zk-tls dApp integration

How to use the zkFetch kind from a dApp: configure the client, write the
policy and the request, collect a threshold, and hand the attestment to the
contract. The [package README](../README.md) explains the terms; the
[attestor guide](attestor-guide.md) covers the operator side.

## Client setup

`zkFetchClient.init` takes:

- **`trusted`.** The attestors your app pins, built with `@txpipe/thoth-client`'s
  `buildTrustedSet({ registrySize, attestors })`. `registrySize` is your
  registry's `#M`; each member pairs an attestor's descriptor
  (`{ id, definition, publicKey }`) with the `registryIndex` of its key in your
  deployed registry. The attestor does not choose its slot.
- **`transport`.** How the client reaches each attestor. You supply it; the
  attestor side is `Attestor.attest`, and `@txpipe/thoth-client` has a minimal HTTP
  example.
- **`verifier`.** The attestor signature verifier. For Jubjub Schnorr, use
  `jubjubVerifier` from `@txpipe/thoth-client/jubjub`.
- **`policy`.** The policy every attestor in the set enforces; see
  [Building the policy](#building-the-policy). Every claim carries
  `zkFetchPolicyHashOf(policy)` as its `policyHash`, and your contract must
  seal that hash at deploy or it rejects the claim.
- **`appId`.** The 32 bytes naming your app, signed into every claim. Your
  contract seals the same bytes at deploy and rejects a claim for any other.
- **`valueSlots`.** Your contract's `#V`, the numeric slot count. Each
  attestor caps the slot counts it accepts; check its
  [limits](https://github.com/txpipe-shop/thoth/tree/main/packages/zk-tls#guarantees-and-limits)
  with its operator.
- **`byteSlots`.** Optional: half your contract's `#B`, since the contract
  stores each 32-byte value as two 16-byte halves. Defaults to `0`.
- **`provers`.** Where evidence comes from, keyed by attestor id. Each entry
  points at that attestor's own witness: `zkFetchProver({ witnessUrl })`, or any
  object with a `prove(request)` method. Every attestor in `trusted` needs an
  entry, and every entry needs an attestor.

A complete setup:

```ts
import { buildTrustedSet, type AttestorTransport } from '@txpipe/thoth-client';
import { jubjubVerifier } from '@txpipe/thoth-client/jubjub';
import { holderCommitmentOf } from '@txpipe/thoth-core/claim-context';
import { type ZkFetchDefinition, zkFetchPolicySchema } from '@txpipe/thoth-zk-tls';
import { zkFetchClient } from '@txpipe/thoth-zk-tls/client';
import { zkFetchProver } from '@txpipe/thoth-zk-tls/prover';

const trusted = buildTrustedSet({
  registrySize: 3, // the registry's #M
  attestors: [
    { attestor: txpipeDescriptor, registryIndex: 0 },
    { attestor: eryxDescriptor, registryIndex: 1 },
    { attestor: foundationDescriptor, registryIndex: 2 },
  ],
});

// JSON carries neither bigint nor bytes, so toJson and fromJson (defined in the
// @txpipe/thoth-client README) tag them; your attestor's server must decode with the same pair.
const transport: AttestorTransport<ZkFetchDefinition, PublicKey, Signature> = {
  async request(attestor, input) {
    const res = await fetch(`https://${attestor.id}/attest`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: toJson(input),
    });
    if (!res.ok) throw new Error(`attestor ${attestor.id} rejected: ${res.status}`);
    return fromJson(await res.text());
  },
};

const policy = zkFetchPolicySchema.parse({
  allowedHosts: ['www.strava.com'],
  slots: [
    { slot: 0, name: 'distance', parse: 'float' },
    { slot: 1, name: 'movingTime', parse: 'int' },
  ],
  // The disclosure rules the witness executes. The client proves every
  // request with these.
  responseMatches: [
    { type: 'regex', value: '"distance":\\s*(?<distance>[\\d.]+)' },
    { type: 'regex', value: '"moving_time":\\s*(?<movingTime>\\d+)' },
  ],
  responseRedactions: [{ regex: '"distance":\\s*[\\d.]+' }, { regex: '"moving_time":\\s*\\d+' }],
  // Safe only if a body cannot change this endpoint's response at any layer.
  bodyPolicy: 'ignored',
});

const client = zkFetchClient.init({
  trusted,
  transport,
  verifier: jubjubVerifier,
  policy,
  appId, // 32 bytes
  valueSlots: 2, // the contract's #V
  provers: {
    [txpipeDescriptor.id]: zkFetchProver({ witnessUrl: 'wss://witness.txpipe.example/ws' }),
    [eryxDescriptor.id]: zkFetchProver({ witnessUrl: 'wss://witness.eryx.example/ws' }),
    [foundationDescriptor.id]: zkFetchProver({ witnessUrl: 'wss://witness.foundation.example/ws' }),
  },
});

// holderSecret: 32 cryptographically random bytes, fresh per claim, kept locally.
const holder = holderCommitmentOf(holderSecret);
const start = Math.floor(Date.now() / 1000);
const proved = await client.proveReq(
  {
    url: 'https://www.strava.com/api/v3/athlete/activities?per_page=1',
    method: 'GET',
    publicHeaders: { accept: 'application/json' },
    secretHeaders: { authorization: `Bearer ${accessToken}` },
    context: { label: 'strava-activity' },
  },
  { holder, windowStart: BigInt(start), windowEnd: BigInt(start + 60) },
);

const attestment = await proved.attest(); // or .attest(txpipeDescriptor.id)
```

`proveReq` fetches through every pinned attestor's witness and requires them
to agree on one claim before any attestor is contacted. Every witness signs
the holder and window through the [claim context](../../../CONTEXT.md#the-claim)
digest ([ADR 0011](../../../docs/adr/0011-evidence-binds-the-claim-context.md)).
Leave room in `windowEnd` for a slow proof: evidence observed after it is
refused (see [Collecting a threshold](#collecting-a-threshold)).
`attest` then asks the named attestors, or all of them, to sign it.

## Collecting a threshold

`collect` does the whole flow in one call and tolerates a down, disagreeing or
invalid attestor:

```ts
const attestment = await client.collect(request, {
  holder,
  windowStart: BigInt(start),
  windowEnd: BigInt(start + 60),
  expiresAt: Date.now() + 60_000,
  threshold: 2,
  attestorTimeoutMs: 20_000,
});
```

- Set the window to the freshness and width your contract accepts. Every
  witness signs under this one window, and `collect` keeps it fixed across
  spares. The prover stamps its observation time after it builds the proof, so
  leave room for a slow proof: evidence observed after `windowEnd` is refused.
- Set `threshold` to your contract's N.
- `expiresAt` is a local deadline, not signed. Give it at least twice
  `attestorTimeoutMs` after the start so a spare can still prove after one
  attestor hangs.
- Pass an ordered `attestorIds` list to choose which witnesses see your secret
  headers, and in which order.

The result is one group of attestations over one message, plus the
`failures` list. The README's
[Guarantees and limits](../README.md#guarantees-and-limits) lists what counts,
what is refused, and what `ZkFetchThresholdError` carries.

## Building the request

`ZkFetchRequest` describes the fetch. The witness signs the URL, method, body
and disclosure rules into the claim, so the policy can rely on them.
`publicHeaders` and `context` are visible to whoever verifies the evidence:
every attestor and anyone the evidence reaches. Only `secretHeaders` are not.
The client adds the claim context digest to `context` under
the `thothClaimContext` key and refuses a request that sets that key itself.
The two fields with protocol meaning:

- `responseMatches` selects what gets certified. A named group
  (`(?<distance>…)`) becomes a disclosed value keyed by the group name; a
  `contains` match only guards the response.
- `responseRedactions` is Reclaim's reveal whitelist, by `regex`, `jsonPath`
  or `xPath`. The selected slices are the only parts of the response the
  witness, and so the evidence, ever sees.

The policy owns both. The client proves every request with the policy's rules:
a request that omits them gets the policy's, and one that supplies its own must
carry exactly the policy's or the client refuses before any witness is
contacted. A slot is certifiable only when a `responseMatches` group extracted
it from a revealed slice, so name the slot exactly like the group. The policy
schema refuses a slot `name` that no `regex` match declares as a named group; a
`contains` match and a redaction regex declare no groups.

Put a per-user URL in the request as a concrete URL
(`https://example.com/user/42`), never as a Reclaim `{{param}}` template.
The witness signs the template text but fetches the URL after filling in
caller-chosen `paramValues`, so a template in the host or the userinfo
(`https://{{x}}@api.example.com/…`) fetches a host outside the policy's
`allowedHosts`, and the subject hash commits to text that was not fetched. The
client and the attestor refuse evidence whose signed URL, body, `geoLocation`
or `proxySessionId` contains `{{`, in the URL also when written as `%7B`/`%7D`
or split by a tab or line break, which URL parsing drops.

The signed URL cannot contain `*`. Reclaim compares a signed `*` as equal to a
[redaction marker](../../../CONTEXT.md#roles) in the transcript, and the caller
chooses which request bytes it redacts, so each `*` would leave a sent byte
unbound. The client and the attestor refuse a `*` in the URL text, and a host
that URL parsing turns into one, as it does with `%2A.example.com` or a
full-width `＊`. Write a literal `*` in the path or query as `%2A`, which
Reclaim compares byte for byte. The subject keeps that spelling, so pass the
`%2A` form to `zkFetchSubjectOf` when you compute the subject hash your
contract expects.

The subject hash binds the **signed** body. An empty body contributes
`sha256('')` and does not bind the body the witness sent: the witness checks the
sent body only when the signed body is non-empty. The policy's
[body policy](#body-policy) decides which signed bodies are accepted.

Whatever you reveal must be identical across independent fetches, because each
witness signs the revealed slice into the claim. A whole-response
`(?<data>.*)` match is not safe: HTTP headers carry per-request values such as
rate limits, dates and request ids, so two witnesses derive different
identifiers and their attestors sign different messages: `proveReq` fails with
`witnesses disagree`, and `collect` cannot count them together. Reveal
only the fields the policy binds, and prefer values the origin returns
deterministically.

## Building the policy

Every attestor in a trusted set enforces the same policy, so keep one policy
object per set and let the client carry it to every request. The fields are
documented on `zkFetchPolicySchema`; the parse rules decide what a disclosed
string becomes.

Numeric rules fill a `Uint<64>` slot:

- `int` accepts decimal digits only and requires a value below `2^64`.
- `float` accepts a whole string matching
  `[0-9]+(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?`: digits, an optional decimal
  point followed by digits, and an optional base-10 exponent. Leading zeros are
  allowed; whitespace, signs, grouping separators, trailing text, `NaN` and
  `Infinity` are not. `12abc`, `1,000`, `.5` and `1.` are invalid; `0.5` and
  `2.5e2` are valid. It rounds in decimal arithmetic to the nearest integer,
  halves up, and requires the result below `2^64`: `9007199254740993` stays
  exact, and `0.49999999999999999999` rounds to zero.

Byte rules fill a 32-byte slot and reject a value that does not fit:

- `bytes` keeps the value's UTF-8 bytes. The limit counts bytes, not
  characters. Trailing NUL bytes merge into the padding and unpaired surrogates
  become U+FFFD, so equality is over the padded bytes, not the source string.
- `hex` decodes hex digits, case-insensitively, with an optional `0x`/`0X`
  prefix. A 64-character key is 32 bytes; a 40-character address is 20.
- `base64` decodes the standard or URL-safe alphabet, with optional `=`
  padding.

What decoding folds and what it keeps as data is in the
[Byte slot](../../../CONTEXT.md#the-claim) entry
([ADR 0010](../../../docs/adr/0010-encoded-byte-rules.md)).

A slot may pin the value's exact byte length with `length` (1–32: the UTF-8
length for `bytes`, the decoded length for `hex` and `base64`). A required slot
whose value is absent, unparseable or off the pinned length rejects the
evidence; an `optional` slot is signed unpresent instead. A numeric rule must
target a numeric slot (`0..V-1`) and a byte rule a byte slot (`V..V+W-1`);
both the client and the attestor reject a policy that crosses the regions.

`responseMatches` and `responseRedactions` are required and part of the policy
hash. The same rules under a different spelling hash the same: array order,
the order of a rule's keys, empty redaction keys and an absent array are inert. The schema refuses
Reclaim's `invert` and `hash` and any `{{param}}` template, so evidence whose
signed rules carry them is refused too.

### Regex engine

Reclaim compiles every `regex` match and every non-empty redaction `regex`
case-insensitively, with `.` matching line breaks. attestor-core uses RE2 with
flags `sgiu` when its optional native `re2` module has loaded, and JavaScript's
`RegExp` otherwise. The two read some patterns differently, so Thoth pins the
engine to RE2:

- `@txpipe/thoth-zk-tls` depends on `re2`. The prover waits for it before its first
  proof and refuses to prove without it.
- Every witness loads `re2` too
  ([attestor guide](attestor-guide.md#running-a-reclaim-witness)).
- `zkFetchPolicySchema` refuses a regex RE2 can't compile, with RE2's reason:

```
regex does not compile under RE2: invalid perl operator: (?=
```

Write policy regexes in [RE2 syntax](https://github.com/google/re2/wiki/Syntax).
It has no lookaround and no backreferences, and a counted repeat is at most
1000.

### Body policy

`bodyPolicy` is required and part of the policy hash. It decides which signed
request bodies the attestor accepts. The witness compares the sent body to the
signed body only when the signed body is non-empty, so the mode is the
difference between a bound body and an explicit risk:

- `non-empty`: the signed body must be non-empty. The witness compares it to
  the sent body, so a caller cannot sign no body and send another. Use it for
  variable bodies, such as a GraphQL query with per-user variables, and for any
  endpoint that can read a body, including a GET or DELETE.
- `{ sha256 }`: the signed body must hash to the pin. Build it with
  `zkFetchBodyHashOf(body)`; the empty body's hash is refused, so use `ignored`
  for an empty signed body. Use a pin for a fixed body, or for a harmless
  sentinel on a bodyless API.
- `ignored`: the signed body must be empty, and the witness does not bind the
  sent body. Use it only when a body cannot change the endpoint's response at
  any layer. Audit the handler and every proxy, WAF and auth layer in front of
  it; a handler that ignores the body is not enough on its own. Otherwise use
  `non-empty` or a pin, even for a GET or DELETE.

Under every mode, the client and the attestor refuse a signed body that
contains `*`. Reclaim's comparison treats a signed `*` as equal to a `*` in the
transcript, and the caller chooses which request bytes it redacts to `*`, so
each one would leave a sent byte unbound. A body that needs a literal `*`
escapes it, for example as `*` in JSON. `zkFetchBodyHashOf` refuses such
a body too.

An endpoint that accepts a body but has nothing to say in it should send a
harmless non-empty sentinel and pin it, rather than using `ignored`:

```ts
import { zkFetchBodyHashOf, type ZkFetchPolicy } from '@txpipe/thoth-zk-tls';

const SENTINEL = '{"thoth":"ignored"}';
const policy: ZkFetchPolicy = {
  allowedHosts: ['api.example.com'],
  // ...
  bodyPolicy: { sha256: zkFetchBodyHashOf(SENTINEL) },
};
// Send SENTINEL as the request body and let the endpoint ignore it.
```

There is no method-based default: a policy that fetches both a bodyless GET and
a POST with a variable body uses one client and policy per body rule (the
contract seals a set of hashes), or sends the same fixed harmless body for both
when both requests can carry it. A witness that compared the body
unconditionally would let `ignored` bind it too, but Reclaim 5.1.6 does not.

The policy has no response-size bound: `responseText` is the transcript as the
client saw it and the witness does not sign it. Limit transport payloads
separately if you need to.

## Handing it to the contract

`attestment.claim` is the claim every attestor signed and `attestment.message`
is its flat encoding; each `attestment.collected[i]` carries the
`registryIndex` your trusted set assigned to the attestor that signed it. Place
each signature at its slot in the contract's fixed signature vector and call
`verifyAttestation` with the claim in the contract's shape,
`toContractClaim(attestment.claim)`, for numeric-only claims too; the
[wire order](../../../docs/DESIGN.md#wire-order) shows that shape.

```ts
import { toContractClaim } from '@txpipe/thoth-core/claim';

// In getAttestationWitness:
const claim = toContractClaim(attestment.claim);
```

See `@txpipe/thoth-contracts` for the circuit and the registry wiring.

Replay protection keys on the signed observation: app id, policy hash, subject
hash, salt, window, values and `present`. The salt is the claim context digest
the witnesses signed, so for one app id and claim shape the same evidence
yields the same claim, and the public nullifier cannot confirm a guessed value
([ADR 0012](../../../docs/adr/0012-nullifier-hashes-a-secret-attestor-derived-salt.md)).
The salt follows the holder, so a new fetch of the same fact under a fresh
holder gets a new nullifier, even in the same window; the contracts README
[says what your app does about it](../../contracts/README.md#guarantees-and-limits).

Recorded evidence lives at
`examples/demo-attestation/fixtures/fixture-github-attestor-core-x-0m.json`
in the repo. It fetches a GitHub repository and discloses the whole HTTP
transcript, headers and body, as one `data` group; the package tests verify it
with the attestor's own verifier.

## Reclaim's hosted zkFetch SDK

`@reclaimprotocol/zk-fetch` is a higher-level prover. You initialize its
`ReclaimClient` with an application id and secret from the Reclaim Developer
Portal, and it handles credentials, witness discovery (the finished proof
carries the `witnesses[].url` it used) and retries. Wrap it as a
`ZkFetchProver` with `toCanonicalEvidence`:

```ts
import { type Options, ReclaimClient } from '@reclaimprotocol/zk-fetch';
import { toCanonicalEvidence, type ZkFetchProver } from '@txpipe/thoth-zk-tls/client';

const hostedProver = (client: ReclaimClient): ZkFetchProver => ({
  prove: async (request) => {
    const proof = await client.zkFetch(
      request.url,
      {
        method: request.method ?? 'GET',
        body: request.body,
        headers: request.publicHeaders,
        // zk-fetch types `context` as { contextAddress, contextMessage } but
        // passes any JSON object to the witness, which signs every key. The
        // client's claim context digest rides in this object.
        context: request.context as Options['context'],
      },
      {
        headers: request.secretHeaders,
        responseMatches: request.responseMatches?.map((match) => ({ ...match })),
        responseRedactions: request.responseRedactions?.map((rule) => ({ ...rule })),
      },
    );
    if (proof === undefined) {
      throw new Error('zk-fetch returned no proof');
    }
    return toCanonicalEvidence(proof);
  },
});
```

Leave `useTee` off. The TEE path hands the context to a native library, and
Thoth has not checked that it keeps the claim context digest; if it drops it,
the client refuses the evidence.

`collect` reports an error from this prover as `evidence`. To report
`transport` or `no-match` instead, throw `ZkFetchProverError` with that reason;
[Guarantees and limits](../README.md#guarantees-and-limits) lists the reasons.

`@reclaimprotocol/zk-fetch` is AGPL-licensed; this package does not depend on
it. Reclaim chooses the witness per call, so this path only fits a trusted set
whose attestors all pin that witness address. Operators who run their own
witnesses need one direct `zkFetchProver` per attestor instead.

References:

- [@reclaimprotocol/zk-fetch README](https://github.com/reclaimprotocol/zk-fetch):
  `ReclaimClient` init, credential modes, `useTee`, `zkEngine`, `geoLocation`,
  and the `witnesses[].url` in the proof output.
- [Reclaim Developer Portal](https://dev.reclaimprotocol.org/): application id
  and secret for the hosted client.
- Reclaim's public witness: `wss://attestor.reclaimprotocol.org:444/ws`, for a
  direct `zkFetchProver` without your own witness.
