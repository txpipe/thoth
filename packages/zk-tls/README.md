# @thoth/zk-tls

A concrete attestor kind for the Thoth N-of-M attestation system: the **zkFetch**
attestor.

Thoth lets Midnight contracts accept externally attested information with ZK
privacy. `@thoth/zk-tls` is the kind that vouches for **what a zk-fetch proof
actually disclosed**: it verifies the Reclaim witness's signature over an HTTPS
fetch, enforces the attestor's policy (host allowlist, pinned witnesses, a
disclosure→slot map), and signs the canonical Thoth `Claim` with the
attestor's own key. It is the Thoth-side consumer of
[Reclaim Protocol](https://github.com/reclaimprotocol) zk-fetch proofs.

## Install

```bash
npm install @thoth/zk-tls
```

## What's in it

The package exposes three entry points. The shared logic (what both sides
need) lives at the package root; the host and client entries depend on it and
add their side's machinery:

- **`@thoth/zk-tls`** — the shared surface, used by both sides:
  - Schemas: `zkFetchEvidenceSchema`, `zkFetchPolicySchema`,
    `zkFetchClaimSchema`.
  - `assertEvidenceMatchesPolicy(verified, policy)` — HTTPS against the host
    allowlist, pinned witness, required slots must be certifiable (disclosed
    and parseable; optional slots may be absent and are signed unpresent),
    size bound.
  - `deriveClaimFromEvidence({ verified, policy, valueSlots })` — derive the
    canonical `Claim` the attestor signs: values/present from the disclosed
    values, a deterministic nonce, and an evidence-bound hash.
  - `parsedEvidenceView(evidence)` — the parsed evidence view claim
    derivation runs on (no signature check; the caller decides trust).
  - `parseDisclosedValue(value, rule)` — the parse law: a disclosed string
    becomes the claim's numeric slot value, or `null` when unparseable or out
    of the wire's `Uint<64>` range.
  - `claimUrl(claim)` — the URL a signed claim attests, decoded from its
    parameters.
  - Types: `ZkFetchDefinition`, `ProviderClaimData`, `ZkFetchEvidence`,
    `VerifiedEvidence`, `ZkFetchPolicy`, `ZkFetchSlot`.
- **`@thoth/zk-tls/attestor`** — the attestor (host) side:
  - `verifyZkFetchProof(evidence)` — verify the witness's ECDSA signature
    with the Reclaim SDK and extract the values it disclosed
    (`VerifiedEvidence.disclosedValues`), dropping redacted fields.
  - `assertClaimMatchesDisclosures({ claim, disclosures, policy })` — enforce
    that a client-proposed claim says exactly what the evidence disclosed.
  - `createZkFetchDefinition()` — the shareable definition: the three schemas
    plus the `verify` step (verify proof → check policy → check claim against
    disclosures) and a `message` that encodes the claim into the flat message
    via `claimToMessage`.
  - `zkFetchAttestor({ id, keyPair, registryIndex })` — a deployable
    instance: a specialization of `@thoth/attestor`'s `buildAttestor` that
    knows the kind and signs the attestor-derived claim at the proposed
    claim's length.
- **`@thoth/zk-tls/client`** — the dApp side: `zkFetchClient`,
  `toCanonicalEvidence`, `addressFromWitnessId`, and the prover/config types.
  `init` validates the policy (including its slot map against the claim
  length) once; `proveReq` binds the prover's evidence to the requested URL's
  origin. The client does **not** re-verify the Reclaim signature — it is the
  side that ran the witnessed interaction, and each pinned attestor verifies
  the evidence before signing.

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

`attestor.attest({ policy, evidence, claim })` parses the input, rejects it if
the evidence is not canonical, does not match the policy, or if the proposed
claim disagrees with the disclosures — then signs the attestor-derived claim.

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

## Concepts

- **Two claims.** A Reclaim *provider claim data* is the record a Reclaim witness
  ECDSA-signs over the fetch (provider, parameters, context, …) — a wire artefact
  Reclaim owns. Thoth's `Claim` is a flat `Vector<K, Field>` a Compact contract
  verifies over Jubjub-Schnorr in zero knowledge. They must differ: a Compact
  circuit cannot verify Reclaim's secp256k1 signature, so the attestor re-signs a
  canonical, circuit-compatible statement. The claim's `evidenceHash` (SHA-256 of
  the canonical evidence) is what binds the one to the other, and lets an app
  holding the evidence independently recompute the mapping.
- **Canonical evidence in.** The attestor accepts one evidence shape only; the
  zod schema is the boundary. Normalizing third-party zkFetch output (raw
  `transformProof` shells, address/witness plumbing) belongs to the producing
  client SDK, not to this trust boundary.
- **Redaction is a law, not a hint.** Reclaim redacts client-side: the witness
  only ever sees selected response slices. The signed parameters
  (`responseRedactions`) declare which extracted names are hidden; those names
  are dropped before anything is certified — redacted fields are **never
  certified**.
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
        │  signs Claim (numeric slots + present + evidenceHash), Jubjub-Schnorr
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
- **The attestor derives its claim.** Rather than trust a client-provided claim,
  the attestor re-derives values from the verified disclosures and only accepts a
  proposal that matches (hence `assertClaimMatchesDisclosures`). The client
  cannot make the attestor certify a reading the evidence does not support.
- **The client does not re-verify.** The client is the side that ran the
  witnessed HTTPS interaction; the Reclaim ECDSA signature is checked by each
  pinned attestor before it signs. The client derives the deterministic
  expected claim from the evidence and `resolveAttestation` forces every
  returned attestation to commit to exactly that message — the on-chain N-of-M
  threshold is the enforcement.
- **Strict input.** Dramatically fewer shapes to reason about at a trust
  boundary, and no witness-address decoding inside the verifier.

## Links

- [Thoth (repo root)](https://github.com/txpipe-shop/thoth) — overall architecture and docs
- [docs/DESIGN.md](https://github.com/txpipe-shop/thoth/blob/main/docs/DESIGN.md) — the attestor kinds, claim/evidence split, and flow
- [`@thoth/core`](https://github.com/txpipe-shop/thoth/tree/main/packages/core) — `AttestorDefinition`, the canonical `Claim` and `claimToMessage`
- [`@thoth/attestor`](https://github.com/txpipe-shop/thoth/tree/main/packages/attestor) — `KeyPair`, `Attestor`, `buildAttestor`
- [`@thoth/contracts`](https://github.com/txpipe-shop/thoth/tree/main/packages/contracts) — the on-chain registry that verifies the signatures positionally
- [Reclaim Protocol attestor-core](https://github.com/reclaimprotocol/attestor-core) — the witness SDK that produces the proofs this kind verifies