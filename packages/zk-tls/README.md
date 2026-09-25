# @thoth/zk-tls

A concrete attestor kind for the Thoth N-of-M attestation system: the **zkFetch**
attestor.

Thoth lets Midnight contracts accept externally attested information with ZK
privacy. `@thoth/zk-tls` is the kind that vouches for **what a zk-fetch proof
actually disclosed**: it verifies the Reclaim witness's signature over an HTTPS
fetch, checks the witness chosen by the attestor operator, enforces the dApp's
policy (host allowlist and disclosure→slot map), and checks the session is bound to the client's
intent, and signs the common Thoth `Claim` with the attestor's own key. It is
the Thoth-side consumer of
[Reclaim Protocol](https://github.com/reclaimprotocol) zk-fetch proofs.

## Install

```bash
npm install @thoth/zk-tls
```

## Getting started

- Build a dApp with `@thoth/zk-tls`: [dApp integration guide](docs/dapp-integration.md).
- Deploy an attestor: [attestor guide](docs/attestor-guide.md).

## What's in it

The package exposes four entry points. The shared logic (what both sides
need) lives at the package root; the host and client entries depend on it and
add their side's machinery. The prover runs a witnessed fetch:

- **`@thoth/zk-tls`** — the shared surface, used by both sides:
  - Schemas: `zkFetchEvidenceSchema`, `zkFetchPolicySchema`,
    `zkFetchClaimSchema`.
  - `assertEvidenceMatchesPolicy(verified, policy)` — HTTPS against the host
    allowlist, required slots must be certifiable (disclosed
    and parseable; optional slots may be absent and are signed unpresent),
    size bound.
  - `assertEvidenceMatchesIntent(verified, intent, policy.maxWindowSeconds)` — the signed context
    carries the intent digest, the signed request matches the request
    binding, and the witness observed inside the policy-bounded intent window.
  - `deriveClaimFromEvidence({ verified, policy, intent, valueSlots })` —
    derive the common `Claim` the attestor signs: the header from the intent
    (with `policyDigest` recomputed from the policy), values/present from the
    disclosed values.
  - Intent helpers: `policyDigestOf(policy)`, `requestBindingOf({ method,
    url, body })`, `intentDigestOf(intent)`, `intentOf(claim)`, and
    `INTENT_CONTEXT_KEY` (the signed-context key carrying the intent digest).
  - `parsedEvidenceView(evidence)` — the parsed evidence view claim
    derivation runs on (no signature check; the caller decides trust).
  - `parseDisclosedValue(value, rule)` — the parse law: a disclosed string
    becomes the claim's numeric slot value, or `null` when unparseable or out
    of the wire's `Uint<64>` range.
  - `claimUrl(claim)` — the URL a signed claim attests, decoded from its
    parameters.
  - Types: `ZkFetchDefinition`, `ProviderClaimData`, `ZkFetchEvidence`,
    `VerifiedEvidence`, `ZkFetchIntent`, `ZkFetchPolicy`, `ZkFetchSlot`.
- **`@thoth/zk-tls/attestor`** — the attestor (host) side:
  - `verifyZkFetchProof(evidence)` — verify the witness's ECDSA signature
    with the Reclaim SDK and extract the values it disclosed
    (`VerifiedEvidence.disclosedValues`).
  - `assertClaimMatchesDisclosures({ claim, disclosures, policy })` — enforce
    that a client-proposed claim says exactly what the evidence disclosed.
  - `createZkFetchDefinition(witnessAddress)` — the definition for one operator-configured
    witness: the three schemas plus the `verify` step (verify proof → check witness → check policy → check intent → check
    the proposed claim equals the derived one) and a `message` that encodes the
    claim into the flat message via `claimToMessage`.
  - `zkFetchAttestor({ id, keyPair, registryIndex, witnessAddress })` — a deployable
    instance: a specialization of `@thoth/attestor`'s `buildAttestor` that
    knows the kind and signs the attestor-derived claim at the proposed
    claim's length.
- **`@thoth/zk-tls/client`** — the dApp side: `zkFetchClient`,
  `toCanonicalEvidence`, `addressFromWitnessId`, and the prover/operator/config
  types. `init` validates the policy (including its slot map against the claim
  length), the operators and the threshold once. `attest(request, { holder,
  windowStart, windowEnd })` builds one intent, runs one witnessed session per
  operator, and returns a threshold attestation (see [Client side](#client-side)).
  The client does **not** re-verify the Reclaim signature — each attestor
  verifies its own witness's evidence before signing — but it does verify every
  attestor signature it counts.
- **`@thoth/zk-tls/prover`** — the live evidence source:
  `zkFetchProver(config)` runs the Reclaim zkFetch protocol against a
  caller-chosen witness over WebSocket and returns canonical evidence for
  an operator's `prover` slot.

## Usage

### Attestor (host) side

Build an instance with a `KeyPair` from the signature scheme's key package.

```ts
import { zkFetchAttestor } from '@thoth/zk-tls/attestor';

const attestor = zkFetchAttestor({
  id: 'zkFetch-strava-1',
  keyPair,
  registryIndex: 0,
  witnessAddress: '0x…40 hex…', // the Reclaim witness this operator trusts
});
```

`attestor.attest({ policy, evidence, claim })` parses the input and runs these
checks in order, rejecting at the first failure:

1. the Reclaim signature is valid;
2. the signer is this instance's configured witness;
3. the attested host is allowed, and the required slots are disclosed and
   parseable;
4. the signed context carries the intent digest;
5. the signed request matches the request binding;
6. the window is not inverted and the witness observed inside it;
7. the proposed claim equals the claim the attestor derives itself.

It then signs its own derived claim. The intent is read off the proposed claim:
its fields are claim fields, and the witness signature over the context digest
is what makes them trustworthy.

The dApp's policy describes which data it wants certified. The attestor operator
configures the witness address on its instance, so a client cannot change witness
trust by changing the policy. The same instance can attest under different
well-formed dApp policies without reconfiguration.

```ts
import { zkFetchPolicySchema } from '@thoth/zk-tls/attestor';

const policy = zkFetchPolicySchema.parse({
  allowedHosts: ['api.strava.com'],
  maxWindowSeconds: 120,
  slots: [
    { slot: 0, name: 'distance', parse: 'float' },
    { slot: 1, name: 'moving_time', parse: 'int' },
  ],
});
```

### Client side

Configure one operator per attestor: the prover that reaches that operator's
witness, and the witness address its attestor pins. Operators are keyed by
attestor id and stay out of the generic trusted set.

```ts
import { zkFetchClient } from '@thoth/zk-tls/client';
import { zkFetchProver } from '@thoth/zk-tls/prover';

const client = zkFetchClient.init({
  trusted,            // @thoth/client buildTrustedSet(...)
  transport,          // how to reach each attestor
  policy,
  valueSlots: 3,
  threshold: 2,       // the contract's N; init rejects more than the operators can meet
  verifier,           // { verify(publicKey, message, signature): boolean }
  operators: {
    txpipe: { prover: zkFetchProver({ witnessUrl: txpipeWitnessUrl }), witnessAddress: txpipeWitness },
    eryx: { prover: zkFetchProver({ witnessUrl: eryxWitnessUrl }), witnessAddress: eryxWitness },
  },
});
const { claim, message, collected, failures } = await client.attest(
  { url: 'https://api.strava.com/…', secretHeaders: { authorization } },
  { holder, windowStart, windowEnd }, // holder: the dApp's 32-byte holder commitment
);
```

One call:

1. builds the intent and puts its digest in the signed request context;
2. runs the witnessed sessions concurrently, one per contacted operator, and
   refuses evidence that is not from that operator's pinned witness or not for
   the requested origin;
3. sends each operator's evidence and derived claim to its attestor — secret
   headers go to the provers only, never to an attestor;
4. checks each returned attestation's key, message and signature;
5. groups the results by exact message and counts distinct registry slots only.

`collected` holds the agreeing attestations sorted by registry slot, ready for
the positional registry.

The client contacts the first `threshold` operators in `operators` order, and
the next one whenever an operator fails or disagrees, until one message reaches
the threshold. `contactAll: true` contacts every operator at once instead;
either way the call returns as soon as the threshold is met. `timeoutMs` bounds
each operator; a late or failed operator never discards another's valid
result. Every operator works under the same intent — the call never retries
with a fresh one — and it gives up once the intent window ends (an intent that
already ended fails before any operator is contacted).

Each operator that did not count gets an `AttestorFailureError` (from
`@thoth/client/errors`) whose `reason` says whether it was `'unreachable'`
(including timeouts), `'rejected'` the request (the message carries its reason),
returned a different `'message'`, or an invalid `'signature'`. On success they
are in `failures`; otherwise `attest` throws an `AggregateError` whose `errors`
hold them.
The client copies no arbitrary prover or transport errors into these failures.

## Concepts

- **The common claim.** The signed claim is
  `version, kind, policyDigest, requestBinding, holder, nonce, windowStart,
  windowEnd, present, values` (`2*V + 8` fields). It carries only facts every
  attestor observing the same intent shares — nothing specific to one piece of
  evidence — so two independent witnesses observing the same fact produce
  byte-identical claims, and the registry can count their signatures together.
- **The intent.** Before any witness is contacted, the client fixes the intent:
  the policy digest (SHA-256 of the policy's canonical serialization), the
  request binding (SHA-256 of the method, URL and body), the holder commitment,
  a random 32-byte operation nonce, and the observation window. Its digest goes
  into the Reclaim request `context` under `thothIntent`, and the witness signs
  that context. That signature binds each witnessed session to the intent; the
  attestor trusts nothing the client asserts without it.
- **Two claims.** A Reclaim *provider claim data* is the record a Reclaim witness
  ECDSA-signs over the fetch (provider, parameters, context, …) — a wire artefact
  Reclaim owns. Thoth's `Claim` is a flat `Vector<K, Field>` a Compact contract
  verifies over Jubjub-Schnorr in zero knowledge. They must differ: a Compact
  circuit cannot verify Reclaim's secp256k1 signature, so the attestor re-signs a
  canonical, circuit-compatible statement. The intent digest in the signed
  context is what binds the one to the other; the claim itself names no
  evidence, so an app that needs the raw evidence keeps it client-side.
- **Canonical evidence in.** The attestor accepts one evidence shape only; the
  zod schema is the boundary. Normalizing third-party zkFetch output (raw
  `transformProof` shells, address/witness plumbing) belongs to the producing
  client SDK, not to this trust boundary.
- **Redaction is a law, not a hint.** Reclaim redacts client-side:
  `responseRedactions` selects the response slices revealed to the witness;
  the rest never reaches it. The reveal plan is part of the signed parameters,
  so an app holding the evidence can recompute what was disclosed. Hidden
  fields cannot be certified.
- **The attestor certifies facts, not decisions.** Values place exactly what the
  evidence disclosed; the app's predicate over the claim slots is the decision.
  A slot whose disclosure is absent (or unparseable under the policy rule) is
  signed as *unpresent* rather than guessed.
- **One policy per attestation.** N-of-M means "N independent attestors agree
  on the same signed message". The dApp sends the same policy to its trusted
  set for a given attestation. The policy digest commits the claim to its slot
  map and parse rules, while each operator independently chooses its witness.

## Design rationale

The kind lands in the middle of the Thoth layering:

```
  Reclaim witness (TLS + proof + signed provider claim)
        │  evidence (ProviderClaimData + signature + address)
        ▼
  @thoth/zk-tls attestor — verify witness signature → policy → disclosures
        │  signs the common Claim (intent header + present + values), Jubjub-Schnorr
        ▼
  N-of-M of these → @thoth/contracts registry (Midnight)
```

- **Composition with the host.** The definition binds the common law to the
  operator's `witnessAddress`. The `KeyPair` and `registryIndex` complete the
  deployable instance. `@thoth/attestor`'s `AttestorSigner` owns the signing key.
- **Shared logic at the root.** The `@thoth/zk-tls` root holds what both sides
  need (schemas, policy check, claim derivation, parse law); a client-only app
  never imports `@thoth/attestor` or the host machinery, and the Reclaim
  signature work lives only in the attestor entry.
- **The prover is a separate entry.** Its subpath keeps the Reclaim client
  stack out of apps that do not run witnessed fetches. It uses lazy imports,
  no Node built-ins, and a caller-supplied witness URL and auth request.
- **The attestor derives its claim.** Rather than trust a client-provided claim,
  the attestor re-derives values from the verified disclosures and only accepts a
  proposal that matches (hence `assertClaimMatchesDisclosures`). The client
  cannot make the attestor certify a reading the evidence does not support.
- **The client does not re-verify the witness.** The client is the side that
  ran the witnessed HTTPS interaction; each attestor checks the Reclaim ECDSA
  signature and its configured witness address before signing. The client
  derives the deterministic expected claim from the intent and each operator's
  evidence, and `resolveAttestation` forces every returned attestation to
  commit to exactly that message under a valid signature.
- **Grouping, not trusting.** Two honest witnesses of the same fact produce the
  same claim, so the client groups by exact message and never merges different
  observations. A threshold counts registry slots, not responses.
- **Operators are kind configuration.** A zkFetch operator is a witness plus an
  attestor; the witness part means nothing to other kinds, so the
  `operators` map lives in the zkFetch client config, not in `@thoth/client`'s
  trusted set.
- **Fallback on demand, one intent per call.** By default the client contacts
  only `threshold` operators and adds one whenever no message can still reach
  the threshold, so a healthy set costs `threshold` witnessed sessions;
  `contactAll` trades sessions for latency. Every operator witnesses under the
  same intent and the call never retries with a fresh one, so the agreeing
  signatures always commit to one observation window and nonce.
- **Rejected versus unreachable.** A transport cannot know what an arbitrary
  error means, so only an explicit `AttestorFailureError('rejected')` counts
  as a refusal; everything else a transport throws is `'unreachable'`. The
  client's own pre-send evidence checks apply the attestor's law, so they
  report `'rejected'` too. Arbitrary prover errors are classified without
  copying their messages into public failures.
- **Strict input.** Dramatically fewer shapes to reason about at a trust
  boundary, and no witness-address decoding inside the verifier.

## Links

- [Thoth (repo root)](https://github.com/txpipe-shop/thoth) — overall architecture and docs
- [docs/DESIGN.md](https://github.com/txpipe-shop/thoth/blob/main/docs/DESIGN.md) — the attestor kinds, claim/evidence split, and flow
- [dApp integration guide](docs/dapp-integration.md) — client setup and submitting an attestment
- [attestor guide](docs/attestor-guide.md) — running a zkFetch attestor and Reclaim witness
- [`@thoth/core`](https://github.com/txpipe-shop/thoth/tree/main/packages/core) — `AttestorDefinition`, the canonical `Claim` and `claimToMessage`
- [`@thoth/attestor`](https://github.com/txpipe-shop/thoth/tree/main/packages/attestor) — `KeyPair`, `Attestor`, `buildAttestor`
- [`@thoth/contracts`](https://github.com/txpipe-shop/thoth/tree/main/packages/contracts) — the on-chain registry that verifies the signatures positionally
- [Reclaim Protocol attestor-core](https://github.com/reclaimprotocol/attestor-core) — the witness SDK that produces the proofs this kind verifies
