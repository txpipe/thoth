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

The package exposes two entry points — one per side of the kind:

- **`@thoth/zk-tls/attestor`** — the attestor (host) side:
  - `createZkFetchDefinition()` — the kind's shareable, keyless law: the
    policy/evidence/claim schemas plus the three-step `verify` (verify proof →
    check policy → check claim against disclosures), and a `message` that encodes
    the claim into the flat message via `claimToMessage`.
  - `zkFetchAttestor({ id, keyPair, registryIndex })` — a deployable
    instance: a specialization of `@thoth/attestor`'s `buildAttestor` that knows
    the kind and signs the attestor-derived claim at the proposed claim's length.
  - `verifyZkFetchProof(evidence)` — verify the witness's signature with the
    Reclaim SDK and extract the values it disclosed
    (`VerifiedEvidence.disclosedValues`), dropping redacted fields.
  - `assertEvidenceMatchesPolicy(verified, policy)` — host allowlist, pinned
    witness, required slots must be certifiable (disclosed and parseable;
    optional slots may be absent and are signed unpresent), size bound.
  - `deriveClaimFromEvidence({ verified, policy, valueSlots })` — derive the
    canonical `Claim` the attestor signs: values/present from the disclosed
    values, a deterministic nonce, and an evidence-bound hash.
  - `assertClaimMatchesDisclosures({ claim, disclosures, policy })` — enforce
    that a client-proposed claim says exactly what the evidence disclosed.
  - Schemas and types: `zkFetchClaimSchema`, `zkFetchEvidenceSchema`,
    `zkFetchPolicySchema`, `ProviderClaimData`, `ZkFetchEvidence`,
    `VerifiedEvidence`, `ZkFetchPolicy`, `ZkFetchSlot`.

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
- **The attestor derives its claim.** Rather than trust a client-provided claim,
  the attestor re-derives values from the verified disclosures and only accepts a
  proposal that matches (hence `assertClaimMatchesDisclosures`). The client
  cannot make the attestor certify a reading the evidence does not support.
- **Strict input.** Dramatically fewer shapes to reason about at a trust
  boundary, and no witness-address decoding inside the verifier.

## Links

- [Thoth (repo root)](https://github.com/txpipe-shop/thoth) — overall architecture and docs
- [docs/DESIGN.md](https://github.com/txpipe-shop/thoth/blob/main/docs/DESIGN.md) — the attestor kinds, claim/evidence split, and flow
- [`@thoth/core`](https://github.com/txpipe-shop/thoth/tree/main/packages/core) — `AttestorDefinition`, the canonical `Claim` and `claimToMessage`
- [`@thoth/attestor`](https://github.com/txpipe-shop/thoth/tree/main/packages/attestor) — `KeyPair`, `Attestor`, `buildAttestor`
- [`@thoth/contracts`](https://github.com/txpipe-shop/thoth/tree/main/packages/contracts) — the on-chain registry that verifies the signatures positionally
- [Reclaim Protocol attestor-core](https://github.com/reclaimprotocol/attestor-core) — the witness SDK that produces the proofs this kind verifies