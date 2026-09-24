# @thoth/zk-tls

A concrete attestor kind for the Thoth N-of-M attestation system: the **zkFetch**
attestor.

Thoth lets Midnight contracts accept externally attested information with ZK
privacy. `@thoth/zk-tls` is the kind that vouches for **what a zk-fetch proof
actually disclosed**: it verifies the Reclaim witness's signature over an HTTPS
fetch, enforces the attestor's policy (host allowlist, pinned witnesses, a
disclosure→slot map), checks the witnessed session is bound to the client's
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
    allowlist, pinned witness, required slots must be certifiable (disclosed
    and parseable; optional slots may be absent and are signed unpresent),
    size bound.
  - `assertEvidenceMatchesIntent(verified, intent)` — the signed context
    carries the intent digest, the signed request matches the request
    binding, and the witness observed inside the intent window.
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
  - `createZkFetchDefinition()` — the shareable definition: the three schemas
    plus the `verify` step (verify proof → check policy → check intent → check
    the proposed claim equals the derived one) and a `message` that encodes the
    claim into the flat message via `claimToMessage`.
  - `zkFetchAttestor({ id, keyPair, registryIndex })` — a deployable
    instance: a specialization of `@thoth/attestor`'s `buildAttestor` that
    knows the kind and signs the attestor-derived claim at the proposed
    claim's length.
- **`@thoth/zk-tls/client`** — the dApp side: `zkFetchClient`,
  `toCanonicalEvidence`, `addressFromWitnessId`, and the prover/config types.
  `init` validates the policy (including its slot map against the claim
  length) once; `proveReq(request, { holder, windowStart, windowEnd })` builds
  the intent, puts its digest in the signed request context, and binds the
  prover's evidence to the requested URL's origin. The client does **not**
  re-verify the Reclaim signature — it is the side that ran the witnessed
  interaction, and each pinned attestor verifies the evidence before signing.
- **`@thoth/zk-tls/prover`** — the live evidence source:
  `zkFetchProver(config)` runs the Reclaim zkFetch protocol against a
  caller-chosen witness over WebSocket and returns canonical evidence for
  the client's `prover` slot.

## Usage

### Attestor (host) side

Build an instance with a `KeyPair` from the signature scheme's key package.

```ts
import { zkFetchAttestor } from '@thoth/zk-tls/attestor';

const attestor = zkFetchAttestor({
  id: 'zkFetch-strava-1',
  keyPair,
  registryIndex: 0,
});
```

`attestor.attest({ policy, evidence, claim })` parses the input and runs these
checks in order, rejecting at the first failure:

1. the Reclaim signature is valid;
2. the signer is a pinned witness;
3. the attested host is allowed, and the required slots are disclosed and
   parseable;
4. the signed context carries the intent digest;
5. the signed request matches the request binding;
6. the window is not inverted and the witness observed inside it;
7. the proposed claim equals the claim the attestor derives itself.

It then signs its own derived claim. The intent is read off the proposed claim:
its fields are claim fields, and the witness signature over the context digest
is what makes them trustworthy.

The policy pins the witness trust:

```ts
import { zkFetchPolicySchema } from '@thoth/zk-tls/attestor';

const policy = zkFetchPolicySchema.parse({
  allowedHosts: ['api.strava.com'],
  attestorAddresses: ['0x…40 hex…'],      // which Reclaim witness may sign evidence
  slots: [
    { slot: 0, name: 'distance', parse: 'float' },
    { slot: 1, name: 'moving_time', parse: 'int' },
  ],
});
```

### Client side

```ts
import { zkFetchClient } from '@thoth/zk-tls/client';

const client = zkFetchClient.init({ trusted, transport, policy, valueSlots: 3, prover });
const proof = await client.proveReq(
  { url: 'https://api.strava.com/…' },
  { holder, windowStart, windowEnd }, // holder: the dApp's 32-byte holder commitment
);
const { claim, message, collected } = await proof.attest();
```

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
- **One policy per trusted set.** N-of-M only means "N independent attestors
  agree on the same signed message". The contract cannot see what a slot means,
  so every attestor in a pinned trusted set must share the exact same law —
  same `V`, slot map, parse rules, and encoding. Message equality then enforces
  semantic agreement in practice: different interpretations of the same evidence
  produce different messages, and the registry refuses to count them together.

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

- **Composition with the host.** The definition is the shareable law; the
  `KeyPair` + `registryIndex` make the deployable instance. Nothing here owns a
  private key — `@thoth/attestor`'s `AttestorSigner` is the key boundary.
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
- **The client does not re-verify.** The client is the side that ran the
  witnessed HTTPS interaction; the Reclaim ECDSA signature is checked by each
  pinned attestor before it signs. The client derives the deterministic
  expected claim from the intent and the evidence and `resolveAttestation` forces every
  returned attestation to commit to exactly that message — the on-chain N-of-M
  threshold is the enforcement.
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
