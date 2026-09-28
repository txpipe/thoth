# @thoth/zk-tls

A concrete implementation of a kind for Thoth's N-of-M attestation system, named zk-tls.

Thoth lets Midnight contracts accept externally attested information with ZK
privacy. `@thoth/zk-tls` is the kind that vouches for what a zk-fetch proof
disclosed. It verifies the Reclaim witness's signature over an HTTPS fetch,
enforces the attestor's policy, a host allowlist plus a disclosure-to-slot map,
and signs the canonical Thoth `Claim` with the attestor's own key. It consumes
[Reclaim Protocol](https://github.com/reclaimprotocol) zk-fetch proofs.

## Install

```bash
npm install @thoth/zk-tls
```

## Getting started

- Build a dApp that utilizes `@thoth/zk-tls`: [docs/dapp-integration.md](docs/dapp-integration.md).
- Deploy an attestor: [docs/attestor-guide.md](docs/attestor-guide.md).

## What's in it

The package exposes four entry points. The shared logic, which both sides
need, lives at the package root; the host and client entries depend on it and
add their side's machinery. The prover implements an instance of the ZkFetch
prover that the client can use to obtain evidence:

- **`@thoth/zk-tls`:**
  - Schemas: `zkFetchEvidenceSchema`, `zkFetchPolicySchema`,
    `zkFetchClaimSchema`.
  - `assertEvidenceMatchesPolicy(verified, policy)` checks HTTPS against the host
    allowlist and the size bound. Required slots must be
    certifiable, meaning disclosed and parseable; optional slots may be absent
    and are signed unpresent.
  - `deriveClaimFromEvidence({ verified, policy, valueSlots, timestamp })` derives
    the canonical `Claim` the attestor signs: values/present from the disclosed
    values, a deterministic nonce, and the Reclaim identifier as `evidenceHash`.
  - `parsedEvidenceView(evidence)` returns the parsed evidence view claim
    derivation runs on, without a signature check; the caller decides trust.
  - `parseDisclosedValue(value, rule)` applies the parse law: a disclosed string
    becomes the claim's numeric slot value, or `null` when unparseable or out
    of the wire's `Uint<64>` range.
  - `claimUrl(claim)` returns the URL a signed claim attests, decoded from its
    parameters.
  - `zkFetchPolicyHashOf(policy)` hashes a parsed, normalized policy under the
    `zk-fetch@1` law (`ZK_FETCH_LAW`) and the policy's claim version, so
    policies that differ only in defaults, host order or slot order hash the
    same.
  - `zkFetchSubjectOf(request)` builds the kind's subject struct, one SHA-256
    per request part (method, host, path, body), and
    `zkFetchSubjectHashOf(request)` hashes it. The host is its own field so an
    app can compare the host digest in-circuit and keep the path private.
  - Types: `ZkFetchDefinition`, `ProviderClaimData`, `ZkFetchEvidence`,
    `VerifiedEvidence`, `ZkFetchPolicy`, `ZkFetchSlot`, `ZkFetchRequest`,
    `ZkFetchSubject`.
- **`@thoth/zk-tls/attestor`.** The attestor, or host, side:
  - `verifyZkFetchProof(evidence)` verifies the witness's ECDSA signature
    with the Reclaim SDK and extracts the values it disclosed, returned as
    `VerifiedEvidence.disclosedValues`.
  - `assertClaimMatchesDisclosures({ claim, disclosures, policy })` enforces
    that a client-proposed claim says exactly what the evidence disclosed.
  - `createZkFetchDefinition()` returns the shareable definition: the three
    schemas, the `verify` step, which verifies the proof, checks the policy,
    bounds the proposed timestamp by `maxSkewS`, and checks the claim against
    the disclosures, and a `message` that encodes the claim into the flat
    message via `claimToMessage`.
  - `zkFetchAttestor({ id, keyPair, registryIndex, witnessKey })` returns a
    deployable instance: a specialization of `@thoth/attestor`'s `buildAttestor`
    that knows the kind, accepts evidence only from the witness `witnessKey`
    names, and signs the attestor-derived claim at the proposed claim's length.
- **`@thoth/zk-tls/client`.** The dApp side: `zkFetchClient`,
  `toCanonicalEvidence`, `addressFromWitnessId`, and the prover/config types.
  `init` validates the policy, its slot map, and the prover map, once;
  `proveReq` fetches through each attestor's prover, signs a fresh nonce into the
  context, and requires every witness to agree on one claim before any attestor
  is contacted. The client does not re-verify the Reclaim signature. It is the
  side that ran the witnessed interaction, and each pinned attestor verifies
  the evidence before signing.
- **`@thoth/zk-tls/prover`.** The live evidence source:
  `zkFetchProver(config)` runs the Reclaim zkFetch protocol against a
  caller-chosen witness over WebSocket and returns the canonical
  `ZkFetchEvidence` the client's `provers` map expects.

## Concepts

- **Two claims.** A Reclaim provider claim data is the record a Reclaim witness
  ECDSA-signs over the fetch: provider, parameters, context, and more. Reclaim
  owns that wire artefact. Thoth's `Claim` is a flat `Vector<K, Field>` a
  Compact contract verifies over Jubjub-Schnorr in zero knowledge. They must
  differ. A Compact circuit cannot verify Reclaim's secp256k1 signature, so the
  attestor re-signs a canonical, circuit-compatible statement. The claim's
  `evidenceHash` is the Reclaim claim identifier, which covers the request,
  context, and disclosed values. Every witness computes the same identifier for
  the same observation, and an app holding the evidence can independently
  recompute the mapping.
- **Canonical evidence in.** The attestor accepts one evidence shape only; the
  zod schema is the boundary. Normalizing third-party zkFetch output, such as
  raw `transformProof` shells and address/witness plumbing, belongs to the
  producing client SDK, not to this trust boundary.
- **Redaction is a law, not a hint.** Reclaim redacts client-side:
  `responseRedactions` selects the slices revealed to the witness, and the rest
  of the response never reaches it. The reveal plan is part of the signed
  parameters, so an app holding the evidence can recompute exactly what was
  disclosed. Hidden fields cannot be certified.
- **The attestor certifies facts, not decisions.** Values place exactly what the
  evidence disclosed; the app's predicate over the claim slots is the decision.
  A slot whose disclosure is absent, or unparseable under the policy rule, is
  signed as unpresent rather than guessed.
- **One policy per trusted set.** N-of-M only means "N independent attestors
  agree on the same signed message". The contract cannot see what a slot means,
  so every attestor in a pinned trusted set must share the exact same law: same
  `V`, slot map, parse rules, and encoding. Message equality then enforces
  semantic agreement in practice: different interpretations of the same evidence
  produce different messages, and the registry refuses to count them together.
  The policy constrains hosts and slot semantics; which witness an attestor
  trusts is per instance, via its `witnessKey`, not part of the shared law.
  The policy is the dApp's law, carried with each request and enforced by the
  attestor for that request; an attestor holds no app-specific policy. Keeping
  a claim meaningful is the consuming contract's job: it pins the trusted set
  and the predicate, and a claim's values are not source-bound on-chain.

## Live check

Two real witnesses fetching the same request must derive one claim. That needs
network and witness processes, so it lives in `test/live.test.ts` and is skipped
unless `WITNESS_URLS` names at least two witnesses.

Start two witnesses with the helper (clones and pins `attestor-core`, installs
dependencies, runs two sidecars; Ctrl-C stops them):

```bash
npm run witnesses --workspace=packages/zk-tls
```

It prints the check command for another shell:

```bash
WITNESS_URLS=ws://localhost:8001/ws,ws://localhost:8002/ws \
  npx vitest run packages/zk-tls/test/live.test.ts
```

The clone is pinned to `attestor-core` `7d8b90c` (5.1.4) so the check does not
drift with upstream; `WITNESS_REF`, `WITNESS_CLONE_DIR`, `WITNESS_PORT_A/B`, and
`WITNESS_KEY_A/B` override the defaults. The test reveals only the
`stargazers_count` field of `https://api.github.com/repos/txpipe/dolos`
(override with `LIVE_URL`), asserts that both witnesses derive the same
identifier and message, and that the star count is present. It is not part of
`npm test`.

## Design rationale

The kind sits in the middle of the Thoth layering:

```
  Reclaim witnesses (one per attestor: TLS + proof + signed provider claim)
        │  evidence (ProviderClaimData + signature + address)
        ▼
  @thoth/zk-tls attestor — verify own witness's signature → policy → disclosures
        │  signs Claim (numeric slots + present + evidenceHash), Jubjub-Schnorr
        ▼
  N-of-M of these → @thoth/contracts registry (Midnight)
```

- **Composition with the host.** The definition is the shareable law; the
  `KeyPair` + `registryIndex` make the deployable instance. Nothing here owns a
  private key. `@thoth/attestor`'s `AttestorSigner` is the key boundary.
- **Shared logic at the root.** The `@thoth/zk-tls` root holds what both sides
  need: schemas, policy check, claim derivation, and parse law. A client-only
  app never imports `@thoth/attestor` or the host machinery; the Reclaim
  signature work lives only in the attestor entry.
- **The prover is a separate entry.** The concrete `ZkFetchProver` lives behind
  its own subpath so a client-only app never pulls the Reclaim client stack; it
  is environment-neutral, using lazy imports and no Node built-ins, and takes
  the witness URL and auth request from the caller, so the trust anchor stays
  explicit.
- **The attestor derives its claim.** Rather than trust a client-provided claim,
  the attestor re-derives values from the verified disclosures and only accepts
  a proposal that matches, checked by `assertClaimMatchesDisclosures`. The
  client cannot make the attestor certify a reading the evidence does not
  support.
- **The client does not re-verify.** The client is the side that ran the
  witnessed HTTPS interaction; each attestor checks the Reclaim ECDSA signature
  and that it came from its own witness before signing. The client derives the
  deterministic expected claim from the evidence, and `resolveAttestation`
  forces every returned attestation to commit to exactly that message. The
  on-chain N-of-M threshold is the enforcement.
- **Strict input.** Fewer shapes to reason about at a trust boundary, and no
  witness-address decoding inside the verifier.

## Links

- [Thoth (repo root)](https://github.com/txpipe-shop/thoth): overall architecture and docs
- [docs/DESIGN.md](https://github.com/txpipe-shop/thoth/blob/main/docs/DESIGN.md): the attestor kinds, claim/evidence split, and flow
- [docs/postmortem-zk-tls-redaction.md](https://github.com/txpipe-shop/thoth/blob/main/docs/postmortem-zk-tls-redaction.md): why `responseRedactions` is a reveal whitelist, and the bug that proved it
- [docs/dapp-integration.md](https://github.com/txpipe-shop/thoth/blob/main/packages/zk-tls/docs/dapp-integration.md): the dApp guide, from client setup to handing the attestment to the contract
- [docs/attestor-guide.md](https://github.com/txpipe-shop/thoth/blob/main/packages/zk-tls/docs/attestor-guide.md): deploying a zkFetch attestor and running a Reclaim witness
- [`@thoth/core`](https://github.com/txpipe-shop/thoth/tree/main/packages/core): `AttestorDefinition`, the canonical `Claim` and `claimToMessage`
- [`@thoth/attestor`](https://github.com/txpipe-shop/thoth/tree/main/packages/attestor): `KeyPair`, `Attestor`, `buildAttestor`
- [`@thoth/contracts`](https://github.com/txpipe-shop/thoth/tree/main/packages/contracts): the on-chain registry that verifies the signatures positionally
- [Reclaim Protocol attestor-core](https://github.com/reclaimprotocol/attestor-core): the witness SDK that produces the proofs this kind verifies
- [Reclaim Protocol zk-fetch](https://github.com/reclaimprotocol/zk-fetch): the hosted-witness client; see the hosted-network adapter in [the dApp guide](docs/dapp-integration.md#reclaims-hosted-witness-network)