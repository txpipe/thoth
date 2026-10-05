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
    allowlist. Required slots must be certifiable, meaning disclosed and parseable; optional slots may be absent
    and are signed unpresent.
  - `deriveClaimFromEvidence({ verified, policy, appId, holder, valueSlots, windowStart, windowEnd })`
    derives the canonical `Claim` the attestor signs: values/present from the
    disclosed values, `zkFetchSubjectHashOf` the signed
    request as `subjectHash`, and `zkFetchPolicyHashOf(policy)` as
    `policyHash`.
  - `claimRequestOf(claim)` reads the method, URL and body the witness signed
    into the Reclaim claim's parameters: the request the subject hash is over.
  - `parsedEvidenceView(evidence)` returns the parsed evidence view claim
    derivation runs on, without a signature check; the caller decides trust.
  - `parseDisclosedValue(value, rule)` applies the parse law: a disclosed string
    becomes the claim's numeric slot value, or `null` when unparseable or out
    of the wire's `Uint<64>` range.
  - `claimUrl(claim)` returns the URL a signed claim attests, decoded from its
    parameters.
  - `normalizePolicy(policy)` parses a policy, fills its defaults, lowercases,
    deduplicates and sorts its hosts, and sorts its slots by index, so policies
    that mean the same thing normalize the same. The hash and the checks read
    it.
  - `zkFetchPolicyHashOf(policy)` hashes a normalized policy under the
    `zk-fetch@1` law (`ZK_FETCH_LAW`) and the policy's claim version, so
    policies that differ only in defaults, host order or slot order hash the
    same.
  - `zkFetchSubjectOf(request)` builds the kind's subject struct, one SHA-256
    per request part (method, host, path, body), and
    `zkFetchSubjectHashOf(request)` hashes it. The host is its own field so an
    app can compare the host digest in-circuit and keep the path private.
  - Types: `ZkFetchDefinition`, `ProviderClaimData`, `ZkFetchEvidence`,
    `VerifiedEvidence`, `ZkFetchPolicy`, `ZkFetchSlot`, `ZkFetchSubjectRequest`,
    `ZkFetchSubject`.
- **`@thoth/zk-tls/attestor`.** The attestor, or host, side:
  - `verifyZkFetchProof(evidence)` verifies the witness's ECDSA signature
    with the Reclaim SDK and extracts the values it disclosed, returned as
    `VerifiedEvidence.disclosedValues`. Verification leaves the supplied evidence
    unchanged, including non-canonical context encoding.
  - `assertObservationInWindow({ claim, verified })` enforces that the
    witness observed inside the client-proposed window (ADR 0005). The client
    proposes the window from the earliest to the latest witness observation.
  - `assertClaimMatchesSubject({ claim, verified })` enforces that a
    client-proposed claim's `subjectHash` is the one of the request the witness
    signed.
  - `assertClaimMatchesDisclosures({ claim, disclosures, policy })` enforces
    that a client-proposed claim says exactly what the evidence disclosed.
  - `createZkFetchDefinition()` returns the shareable definition: the three
    schemas, the `verify` step, which verifies the proof, checks the policy,
    requires the witness observation inside the proposed window, and checks the claim against
    the signed request and the disclosures, and a `message` that encodes the claim into the flat
    message via `claimToMessage`.
  - `zkFetchAttestor({ id, keyPair, registryIndex, witnessAddress })` returns a
    deployable instance: a specialization of `@thoth/attestor`'s `buildAttestor`
    that knows the kind, accepts evidence only from the witness `witnessAddress`
    names, and signs the attestor-derived claim at the proposed `values.length`.
    The claim schema requires `present` and `values` to have equal lengths;
    verification rejects policy slot indices outside that length before checking
    the proof. Unused positions are derived as absent and zero-valued, regardless
    of their proposed contents. One instance and signing key can serve contracts
    with different slot counts. Each consuming contract enforces its own fixed `#V`.
- **`@thoth/zk-tls/client`.** The dApp side: `zkFetchClient`,
  `toCanonicalEvidence`, `addressFromWitnessId`, and the prover/config types.
  `init` validates the policy, its slot map, and the prover map, once;
  `proveReq(request, holder)` takes a per-claim holder commitment, fetches through
  each attestor's prover and requires every witness to agree on one claim before any attestor
  is contacted. The client does not re-verify the Reclaim signature. It is the
  side that ran the witnessed interaction, and each pinned attestor verifies
  the evidence before signing.
- **`@thoth/zk-tls/prover`.** The live evidence source:
  `zkFetchProver(config)` runs the Reclaim zkFetch protocol against a
  caller-chosen witness over WebSocket and returns the canonical
  `ZkFetchEvidence` the client's `provers` map expects.

The caller derives `holder` with `holderCommitmentOf(secret)` from
`@thoth/core/claim-context`, using a fresh high-entropy 32-byte secret per claim.
Only the commitment goes to the client and attestors. Keep the secret locally
for the contract witness when vaulting or opening the claim. Secret reuse links
claims; Thoth promises no cross-claim identity or unlinkability.

## Collecting a threshold

`client.collect(request, options)` obtains an N-of-M attestment in one call;
see the [dApp integration guide](docs/dapp-integration.md#collecting-a-threshold)
for an example.

- **Fixed window.** The caller fixes the holder and observation window before
  any attempt starts, so every witness signs under the same window. Choose its
  width to satisfy the contract's freshness rules. `expiresAt` is a local
  deadline only; it is not signed.
- **Resilient.** `collect` starts `threshold` attempts and contacts a spare
  attestor only when no message group can still reach the threshold, so a
  down, disagreeing, or invalid attestor does not fail a healthy subset. Spare
  provers that are never needed do not receive the request. Set `expiresAt` to
  at least the start plus twice `attestorTimeoutMs`, so a spare can still
  prove after one hung attestor times out.
- **Verified and distinct.** Every response passes the same checks as
  `proof.attest()`, then counts once per registry slot within its exact-message
  group. `threshold` comes from the caller; the client cannot read the
  contract's N, so set it to match.
- **Bounded.** `attestorTimeoutMs` covers proving, transport, and verification;
  a late result never proceeds or counts. When a group reaches the threshold,
  `collect` returns without waiting for any other attempt. An attempt that
  times out is dropped but not stopped. Its witness fetch and local ZK proving
  run to completion in the background. Reclaim's `createClaimOnAttestor`
  (`@reclaimprotocol/attestor-core` 5.0.8) accepts no abort signal, so
  `ZkFetchProver.prove` has nothing to pass one to. Terminating the attestor
  client could cut the network side, but only for a private client. The
  prover uses Reclaim's per-URL client pool, which other claims to the same
  witness share.
- **Safe failures.** Errors carry only registry slots and step reasons, never
  remote error text. Both `collect` and `proveReq` refuse evidence that
  carries a secret header value as written, percent-encoded, or JSON-escaped,
  before it reaches an attestor. The prover must still redact; the check
  cannot recognize every transformation of a secret. It fails closed, so a
  very short secret value can match unrelated text and drop a healthy
  attestor as `secret`.

## Concepts

- **Two claims.** A Reclaim provider claim data is the record a Reclaim witness
  ECDSA-signs over the fetch: provider, parameters, context, and more. Reclaim
  owns that wire artefact. Thoth's `Claim` is a flat `Vector<K, Field>` a
  Compact contract verifies over Jubjub-Schnorr in zero knowledge. They must
  differ. A Compact circuit cannot verify Reclaim's secp256k1 signature, so the
  attestor re-signs a canonical, circuit-compatible statement. The claim's
  `subjectHash` is the circuit hash of the request the witness signed, so every
  witness that fetched the same request agrees on it, and an app can recompute
  it in-circuit to bind the source host while the path stays private. The
  claim does not commit to the Reclaim evidence itself.
- **Canonical evidence in.** The attestor accepts one evidence shape only; the
  zod schema is the boundary. Normalizing third-party zkFetch output, such as
  raw `transformProof` shells and address/witness plumbing, belongs to the
  producing client SDK, not to this trust boundary.
- **Captured response text.** `responseText` is untrusted, client-supplied
  transport output. The witness signature does not authenticate it, even after
  proof verification. Policy checks use the signed request and disclosures.
  `maxResponseBytes` has been removed from the policy, schema, and policy hash.
  Existing policy hashes that included it must be recomputed. Applications may
  limit transport payloads separately, but those limits certify no response size.
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
  so every attestor answering a request must enforce the exact same law: same
  `V`, slot map, parse rules, and encoding. Message equality then enforces
  semantic agreement in practice: different interpretations of the same evidence
  produce different messages, and the registry refuses to count them together.
  The policy constrains hosts and slot semantics; which witness an attestor
  trusts is per instance, via its `witnessAddress`, not part of the shared law.
  The policy is the dApp's law, carried with each request and enforced by the
  attestor for that request; an attestor holds no app-specific policy or slot count.
  Keeping a claim meaningful is the consuming contract's job: it pins the trusted set
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

It prints each witness's public address for the attestor's `witnessAddress`
configuration and the check command for another shell:

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

All operators in one trusted set must use the same witness version and behavior.
Re-run this check against candidate witnesses after any witness change and before
rotating the set. See the [attestor guide](docs/attestor-guide.md#witness-agreement-and-upgrades)
for the agreement requirement and upgrade procedure.

## Design rationale

The kind sits in the middle of the Thoth layering:

```
  Reclaim witnesses (one per attestor: TLS + proof + signed provider claim)
        │  evidence (ProviderClaimData + signature + address)
        ▼
  @thoth/zk-tls attestor — verify own witness's signature → policy → disclosures
        │  signs Claim (numeric slots + present + subjectHash), Jubjub-Schnorr
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
  a proposal that matches, checked by `assertClaimMatchesSubject` and
  `assertClaimMatchesDisclosures`. The client cannot make the attestor certify
  a reading, or a source, the evidence does not support.
- **The client verifies attestor signatures.** The client is the side that ran the
  witnessed HTTPS interaction; each attestor checks the Reclaim ECDSA signature
  and that it came from its own witness before signing. The client derives the
  deterministic expected claim from the evidence, and `resolveAttestation`
  checks the pinned key, claim, message binding, and attestor signature
  using the configured verifier. Forged transport responses fail before
  submission. The client does not repeat the witness ECDSA check. The
  on-chain registry still enforces the N-of-M threshold.
- **One window across fallback.** `collect` uses a caller-fixed observation
  window. Extending a window after each fallback would change the signed
  message and discard earlier signatures. The local deadline bounds `collect`
  while the contract remains responsible for signed-window freshness.
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
