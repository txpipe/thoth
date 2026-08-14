> Origin: witness-fitness/docs/ATTESTOR-NETWORK-DESIGN.md — hackathon repo; this copy is authoritative for Thoth.
# Attestor Network — production design for private N-of-M attestation on Midnight

**Status:** Design v1, implementation-ready. Companion to `PRIVATE-N-OF-M-ATTESTATIONS.md`
(feasibility). All claims about Compact/stdlib verified against the repo and Midnight docs;
anything not directly verified is marked `[ESTIMATE]` or `[DECISION NEEDED]`.

---

## 0. What this is

A distributable plugin for the Midnight community: **OpenZeppelin-style Compact modules** that let
any contract "introduce externally attested information" — privately, with an N-of-M trust
threshold — plus the **attestor-runner software** that powers a shared network of independent
attestors, plus a **client SDK** for apps and users.

The plugin is governance-agnostic by construction. The network directory is permissionless; every
app pins its own trust set. If the Midnight Foundation helps recruit and vouch for attestor
runners, that accelerates adoption — but no code path depends on it.

## 1. Product shape

| Artifact | What it is | Who consumes it |
|---|---|---|
| `attestation` Compact module(s) | Embedded, OZ-style; registry + N-of-M verification + optional policies | App developers (import + compose) |
| Attestor-runner software | Evidence-adapter daemon: verify evidence, sign canonical claims with a Jubjub-Schnorr key, publish to the directory | Attestor runners (partners, orgs, community) |
| Client SDK | TS wrapper: build claims, collect signatures, call the contract, manage private state | App developers, end users |
| Network directory | Public list of attestor identities + keys + policies | Everyone (discovery, pinning decisions) |

Deliverable boundaries: this design covers the attestation *mechanism* end to end. Application
mechanics (wagers, streaks, income checks) are app concerns — the module only certifies facts.

## 2. Design principles

1. **Trust is per-app.** The contract verifies against the registry *the app pinned*. Network
   governance is a recommendation layer; it can damage reputation, never an app's guarantees.
2. **Governance is pluggable.** The module ships no governance. Registry updates are wired by the
   app to whatever it wants (fixed at deploy, admin key, app multisig, attestor threshold, ...).
   Docs show all four patterns.
3. **Core vs policy.** Cryptographic validity (signatures, membership, distinctness, claim
   binding, replay) is the core — always enforced. Liveness, staleness, expiry are optional
   policy circuits the app composes. "All or none" is a per-contract choice.
4. **N is a deploy-time constant.** Threshold `#N` is a module generic; the circuit shape is
   fixed at compile time. Different thresholds = different instantiations.
5. **Attestors certify facts, not decisions.** The signed claim is a canonical encoding; the app
   defines the predicate over it. Attestors never know what the claim is used for.

## 3. Architecture

```
 evidence adapters (pluggable)
   zkFetch/TLS  │  direct org attestation  │  sensor  │  human review  │  ...
        │ each adapter produces: verified claim artifacts
        ▼
 attestor runner (notary signer daemon)
   • adapter verifies evidence  (zkFetch: re-verify Reclaim proof with Reclaim SDK)
   • builds canonical claim: { schema, fields, timestamp, optional expiry, nonce }
   • signs with Jubjub-Schnorr key (frozen encoding → parity rule)
   • publishes key + identity + policy to the directory
        │  signature over the canonical encoding
        ▼
 user's client: collects N signatures, encodes claim → Vector<#L, Field>
        ▼
 app contract (embeds attestation module)
   core:     N signatures verify (Schnorr-on-Jubjub)
             each pk is a leaf of the app's registry MerkleTree (path proof)
             N leaves distinct  ·  claim matches expected commitment  ·  nonce fresh (nullifier)
   policies: [optional] liveness window vs signed timestamp
             [optional] expiry vs block time
   app:      predicate P(claim) → app outcome; data never leaves the witness
```

## 4. Contract module spec

### 4.1 Generics and registry

```
module attestation<#N, #D, #L> { ... }        // OZ-style: apps import and instantiate
```

- `#N` — threshold (fixed per deployment; e.g. 2, 3, 5).
- `#D` — registry Merkle depth (2..32; capacity 2^D attestors).
- `#L` — canonical claim length in Fields, entirely app-defined (the plugin ships no claim schema).

Registry (app's own ledger field, seeded at deploy):

```
// DEFAULT (provisional — see §10): claims signed while an attestor was registered
// stay valid until they age out; the app's liveness window bounds exposure (§7).
// * Re-review before v1 freeze: plain MerkleTree would kill ALL old proofs on ANY
//   rotation — stricter, but network churn forces mass re-attestation.
export ledger registry: HistoricMerkleTree<#D, Bytes<32>>;
// ALTERNATIVE: plain MerkleTree — any rotation invalidates every old membership proof.
```

- Leaves are pre-hashed attestor public keys: `persistentHash<JubjubPoint>(pk)` →
  `insertHash(leaf)` (hides the leaf on-chain; privacy-preserving registry).
- **Stable leaf indices**: index an attestor by a stable id (e.g. their key fingerprint),
  never reuse a removed index for a different attestor — avoids the HistoricMerkleTree
  churn hazard documented by Midnight. Removal = `insertIndexDefault(stableIndex)`.
- Rotation = `insertHashIndex(newLeaf, sameStableIndex)` (key refresh keeps history clean).

### 4.2 Core circuits

```
// One signature against one pk, Boolean-returning (non-aborting), so callers can
// count; wraps the Schnorr polyfill (see §4.4). Per app config, the pk may be
// disclosed (accountability) or kept as private witness data (attestor-anonymity):
//   ANONYMITY: pk is private witness; membership path proves "some registered key".
witness getAttestationWitness(): [Claim<#L>, Vector<#N, SchnorrSignature>,
                                  Vector<#N, JubjubPoint>, Vector<#N, MerkleTreePath<#D, Bytes<32>>>]

export circuit verifyAttestation(claim: Vector<#L, Field>): [] {
    // unwrap witness: sigs, pks, paths
    // 1. distinctness: all N pks pairwise distinct (leaf equality)
    // 2. membership: for each i, registry.checkRoot(
    //      merkleTreePathRootNoLeafHash<#D>(paths[i])) && paths[i].leaf == hash(pks[i])
    //    (binding: path.leaf must equal the pk we verified the signature against —
    //     otherwise a witnessed path could be replayed with a different sig)
    // 3. signatures: all N Schnorr verifications pass
    // 4. binding: transientHash(claimEncoding) matches the challenge preimage discipline
    // 5. replay: nullifiers.insert(claim.nonce) — see §4.5
    // [policies composed by the app, see §4.3]
}
```

Design notes:

- **Membership binding is the security-critical line** (mirrors the Midnight
  "restrict-a-circuit-to-a-group" guide): the path's leaf must equal the pk the signature
  verifies against, otherwise a public transaction's path can be copied.
- **Distinctness** is `N` pairwise pk comparisons — cheap field ops, not hashes.
- Fixed `#N` means the circuit verifies exactly N signatures; "at least N" remains available
  via the bounded-slots + count pattern (Witness Fitness `countValidSignatures`) for apps
  that want it — documented, not the default.
- The claim is `Vector<#L, Field>`, and the module is **schema-agnostic**: the plugin defines
  no claim schema — each app's encoding is its own contract with its attestors. Apps serialize
  their typed struct via a pure circuit (Witness Fitness's `encodeAssertion` is one app's
  example). Field order is contract law per app; off-chain signers import the compiled
  `pureCircuits` (parity rule, ARCHITECTURE.md §4).

### 4.3 Optional policy circuits (per-contract config)

```
export struct FreshnessConfig {
    enforceLiveness: Boolean;   // require claim.timestamp >= now - maxAgeSeconds
    maxAgeSeconds: Uint<64>;    // back-dating defense (app policy)
    enforceExpiry: Boolean;     // if claim has expiry, require now < expiry
}

export circuit assertFreshness(claim: Claim<#L>, config: FreshnessConfig): []
// liveness:  assert(blockTimeGte(now - maxAgeSeconds))  — checked vs signed timestamp
// staleness: if (config.enforceExpiry) { if (claim.expiresAt.is_some)
//              assert(blockTimeLte(claim.expiresAt.value)) }  — vs block time (unforgeable)
```

- Each check is an independent circuit; an app imports the ones it wants, or calls
  `assertFreshness` with a config struct (sealed or governance-mutable ledger field).
- Liveness (signed-timestamp window) defends against **back-dating by a compromised key**.
  Expiry (signed by the attestor, enforced against block time) handles **staleness** and
  **attestor liability**. Different scales: days for financial claims, hours for workouts,
  none for "born on".
- Cost: comparisons + one `blockTime*` call per policy — negligible gates `[ESTIMATE]`.

### 4.4 Signature scheme

- v1: the proven Jubjub-Schnorr polyfill (`schnorr.compact`: Poseidon challenge via
  `transientHash`, 2^248 truncation via witness quotient/remainder). Verified against
  Compact 0.31.1; stdlib `jubjubSchnorrVerify` confirmed absent (compile probe in repo).
- Wrapped behind a single module interface (`schnorrVerifyOk`) so the stdlib builtin drops
  in when it ships — one call site, no redesign. The parity rule (off-chain signer imports
  `pureCircuits` for the challenge hash) is unchanged and is the load-bearing invariant.
- Aggregation (BLS/MuSig) deliberately not pursued: BLS needs pairings (absent from stdlib);
  MuSig breaks attestor independence. See feasibility report §4.4.

### 4.5 Vault companion module (optional)

Witness Fitness pattern, extracted: apps that want attest-once/use-many store

```
export struct VaultEntry { holderBinding: Field; timestamp: Uint<32>; expiresAt: Maybe<Uint<32>>; }
export ledger vault: Map<Bytes<32>, VaultEntry>;     // key: persistentCommit(claim, rand)
export ledger nullifiers: Set<Bytes<32>>;            // spent claim nonces — replay protection
```

- `storeCredential` = verifyAttestation + commit + bind to holder (`hashToCurve` pseudonym).
- `spendCredential` = prove knowledge of the commitment opening + holder secret; app
  predicates run over the stored credential without re-attesting.
- Optional: apps that don't want the model don't import it — the core works standalone.

## 5. Attestor-runner software spec

One daemon, pluggable evidence adapters:

```
interface EvidenceAdapter {
    verify(artifacts): Promise<VerifiedClaim>;   // returns typed claim fields
    // zkFetchAdapter:     re-verify Reclaim proof w/ Reclaim SDK (hostWhitelist, redaction)
    // directSigningAdapter: org vouches for claims it controls (employer, issuer, ...)
}

runner loop:
  receive request → adapter.verify() → build canonical claim {
      schemaVersion, provider, fields, timestamp, optional expiry, nonce
    } → sign (Jubjub-Schnorr, frozen encoding) → return signature + claim
  periodic: publish { key, identity, policy, uptime, claimed-verifications } to directory
```

> See also: docs/ATTESTOR-LIBRARY-NOTES.md — aligned attestor shape (spawn-your-own-attestor library, proof-based + corroboration/band shapes).

- **v1 adapters**: zkFetch (the Witness Fitness pipeline, proven) + direct-signing (an org
  signs claims it controls — makes the network useful before any zkFetch integration exists).
- **Key management**: runner keys are the trust anchor — HSM-backed in production, key
  ceremony on onboarding, rotation procedure (`rotateNotary` semantics), no plaintext keys
  in config (`.env` only, never committed; repo rule).
- **Ops**: health endpoint, monotonic counters, structured logs; the directory is the
  reputation surface — uptime and verification counts are public.

## 6. Network model

```
directory (permissionless, append-only)
  attestor A { key, identity, policy, since, uptime, ... }
  attestor B { ... }
  ...
        │ discovery + reputation
        ▼
app developer seeds registry (deploy) with the attestors they trust
        │ per-app pinning  ← the actual security decision
        ▼
app contract verifies against ITS pinned registry
```

- **Bootstrap without the Foundation**: the plugin authors run the first runner(s) (the
  notary signer already exists in this repo); recruit 2–3 more from the community; directory
  is live from day one. Apps pin the runner set they trust.
- **With the Foundation**: they recruit/vouch for partners and promote the plugin — an
  accelerator, not a dependency. No code references them.
- **Directory form (decided): off-chain JSON/website only for v1** — versioned, human- and
  tool-readable. A canonical on-chain registry was considered and dropped: without
  cross-contract calls, no other contract can rely on it in-circuit, so it would be only a
  public noticeboard — no security or correctness value. Revisit only if a concrete need
  appears (e.g. discovery without a website).
- **Reputation** is off-chain and social (history, uptime, who vouches). The contract never
  needs it; it only needs the pinned keys.

## 7. Threat model

| Threat | Defense | Owner |
|---|---|---|
| Attestor key compromised → back-dated claims | Liveness window vs signed timestamp | App (config) |
| Attestor key compromised → forged future claims | Signed expiry (if any) + registry rotation | Attestor + app |
| k-of-N attestor collusion | Threshold N; registry is per-app so collusion is per-app-scoped | Deploy-time |
| Attestor removed → old claims | HistoricMerkleTree: claims stay valid until aged out; app liveness bounds exposure | App (policy) |
| Path replay (copy a public membership proof) | Membership binding: path.leaf == verified pk | Module (core) |
| Claim tampering | Signatures commit to the frozen encoding; encoding binding in-circuit | Module (core) |
| Replay of a signed claim | Claim nonce → nullifier Set | Module (core) |
| Which attestors vouched (user privacy) | Per-app anonymity toggle: pks private witness vs disclosed | App (config) |
| Underlying data leaked | Data is witness-only; predicate results are the only outputs | Module (core) |

## 8. Test plan

1. **Parity roundtrip** (gate, before anything else): off-chain sign → simulator verify →
   accept; tamper one byte → reject. Reuse the existing Witness Fitness roundtrip.
2. **Core matrix** (simulator): N-of-N valid accepted; N−1 rejected; wrong-key rejected;
   non-member pk rejected; duplicate signer rejected; stale nonce rejected; tampered claim
   rejected; path-replay rejected (path of attestor A with attestor B's signature).
3. **Policies**: liveness boundary (now−maxAge ±1s), expiry boundary, each toggle off.
4. **Rotation**: attestor removed → claim signed pre-removal accepted (Historic) / rejected
   (plain); key refreshed → old and new claims behave per policy.
5. **Anonymity**: both toggle settings; witness shape matches; no pk leaks when hidden.
6. **Vault companion**: store → spend → predicate; double-spend blocked; cross-holder spend
   blocked.
7. **Cost probes**: compile with and without policies; gate counts per `#N`, `#D`
   `[ESTIMATE]` — expecting low tens of thousands of constraints at 3-of-M, depth 10.
8. **E2E**: zkFetch attestation → 2 runners sign → on-chain verify → credential stored
   (reuse Witness Fitness demo flow, now through the module).
9. **Runner**: adapter mock tests; real zkFetch test; direct-signing test; key rotation.

## 9. Milestones

| Phase | Deliverable |
|---|---|
| M1 | Module skeleton: `attestation<#N,#D,#L>` core (registry, verifyAttestation, distinctness, binding) + simulator matrix §8.2 |
| M2 | Policies (§4.3) + parity roundtrip + cost probes |
| M3 | Vault companion + anonymity toggle + rotation tests |
| M4 | Runner: adapter interface + zkFetch + direct-signing + directory publishing |
| M5 | Client SDK + reference demo (attest → predicate) + docs + threat-model review |

## 10. Decisions and open questions

**Locked:**
- **Directory**: off-chain JSON/website for v1. On-chain canonical registry dropped — no
  cross-contract calls means other contracts can't rely on it in-circuit; it would only be
  a noticeboard. (§6)
- **Churn policy**: HistoricMerkleTree + stable-index discipline (provisional — below).
- **Membership binding**: required (confirmed). Without it, unregistered keys pass as
  registered by pairing their own signature with a copied membership path.
- **Anonymity**: per-app toggle (disclosed pks vs private witness data).
- **Claim schema**: module is schema-agnostic over `#L`; apps define their own encoding.
  Witness Fitness is an example consumer, not part of the plugin.

**Provisional — re-review before v1 freeze:**
- **HistoricMerkleTree \*** — removal shouldn't retroactively kill claims signed while an
  attestor was registered; compromise exposure is bounded by the app liveness window.
  Tradeoff not fully analyzed: plain MerkleTree gives instant kill-on-removal but every
  rotation forces mass re-attestation across all apps.
- **Liveness demo default** — not a design decision; a config example value (30 days was a
  demo-fixture choice). Set when the demo ships.
