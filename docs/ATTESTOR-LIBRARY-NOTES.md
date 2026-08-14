# Attestor library — aligned design notes

> Status: aligned design notes (brainstorm output), not an implementation plan.
> Conversation-shaped record of the attestor-architecture we converged on for Thoth's
> runner/attestor layer. Companion to `ATTESTOR-NETWORK-DESIGN.md` and the Witness Fitness
> extraction map (`EXTRACTION.md`). Fleshing into a full spec is a separate step.

## The idea in one line

A library (`@thoth/attestor`) you use to **spawn your own attestors**: you write the
custom evidence→claim logic, the library signs, encodes, serves the endpoint, and
generates the Companion Compact module that lets Midnight contracts verify the claim.

## Mental model

- **Evidence in → signed claim out.** That is the whole attestor job, inherited from the
  Witness Fitness notary (POST /attestate → verify proof → build assertion → sign).
- The **contract consumes exactly that signed-claim shape** as input to its circuits.
  Both sides commit to the same frozen encoding — **signature parity is the one invariant**
  that must never break (Witness Fitness `ARCHITECTURE.md` §4).
- **One layer of primitives; no two worlds.** Prebuilt attestors and your hand-rolled ones
  are built from the *identical* building blocks, so the prebuilt ones prove the primitives
  are expressive enough and you are never restricted to a fixed set.
- **You define the plumbing.** Validation, custom types, evidence handling — all yours.
  The library handles the boring, correctness-critical parts: signing, parity encoding,
  HTTP/transport, key management, and generating the per-attestor claim wiring into a
  shared verifier.

## How a user defines an attestor (shapes the whole API)

The config splits the concerns:

- **`source` — mechanism only.** Selects the evidence channel (`zkFetch` | `effectStream` | `tee` | …). Carries nothing else; how a zkFetch attestor differs from a `tee` one is that it proves over a web/TLS proof rather than a hardware enclave quote.
- **`policy` — the parametrization.** All the settings that make an attestor trustworthy: which hosts/events/quotes it accepts, which proof schema it verifies, how strict it is. This object is canonicalized and **hashed into a profile fingerprint that is committed to the signed claim**, so an app can pin "this key attested *under this policy*" and detect drift on-chain. It is the most strictly-typed object in the config — it gets compared on-chain, so no `any`/`unknown` (see Type/strictness rule).
- **`schema` — the claim shape.** The frozen field encoding the claim is signed in. Separate from `policy` on purpose: a policy change flips the profile while `schema` stays frozen, and vice versa.
- **`bindsTo` — scope who may consume the claim.** A stable **logical app id** (e.g. `"io.runrewards.v1"`), folded into the signed claim so an app only accepts claims stamped for itself. `null` (default) = context-free, portable anywhere. Not a contract address — an address is per-deployment and breaks on redeploy/migration; a logical id survives deployment. This is an opt-in *scoping* knob (see amplification note under the shapes), likely wrong for identity/proof-of-person, which wants portability. The app's verifier checks `claim.bindsTo == <configured audience>`.

```ts
const stravaAttestor = thoth.attestor({
  id: "strava-activity",
  source: { type: "zkFetch" },          // mechanism only

  policy: {                              // canonicalized + hashed → profile fingerprint
    hosts: ["www.strava.com"],           //   which origins we'll accept evidence from
    accept: "reclaim-v2",                //   which proof schema we verify
    redaction: "preserve-privacy",       //   what's committed vs left in the witness
    challengeTtlMs: 5_000,               //   response freshness / replay window
  },

  bindsTo: "io.runrewards.v1",           // scope the claim to one app (null = portable)

  schema: {
    id: "strava.activity.v1",
    version: 1,
    fields: [
      { name: "distance", type: "Uint64" },  // meters
      { name: "time",     type: "Uint64" },  // seconds
    ],
  },
  build: async (evidence) => {
    // YOUR code: re-verify the evidence (if any), then return fields to sign
    const ok = verifyEvidence(evidence);
    if (!ok) throw new Error("evidence rejected");
    return { distance: evidence.claims.distance, time: evidence.claims.time };
  },
});

// To make it portable instead (a fact any app may use), omit or null the binding:
//   bindsTo: null,
```

- `build(evidence) => claimFields` is the entire user-supplied function. The library calls
  it, then signs + encodes + serves + generates the verifier.
- **`build` is always "look at the evidence (if any), return the fields to sign."** How much
  proof-checking you do is entirely yours. Evidence comes in as the `build` argument.
- **Verification is generic and parametrized.** A single attestor engine runs the same proof
  verification for everybody; each `policy` object parametrizes it. A provider (e.g. the
  Midnight Foundation) runs one attestor "for everyone" simply by accepting a set of
  `policy` objects — one per schema it vouches for — and each is a distinct verifiable profile.

### effectStream / cross-chain — one attestor per chain

The cross-chain case (deposit/bridge finality) watches a chain for a finality event. As with
identity/proof-of-person, adding a chain is *not a third shape* — same `build` function
shape, different `policy`. Prefer **one attestor per chain**: an effectStream attestor scoped
to `policy.chain: eth` and one scoped to `policy.chain: cardano` are *independent attestors*
the app pins together under N-of-M, each vouching its own side of the same deposit. A single
multi-chain attestor would collapse two independent witnesses into one — the wrong shape for
corroboration.

```ts
const ethDepositAttestor = thoth.attestor({
  id: "eth-deposit",
  source: { type: "effectStream" },      // mechanism only

  policy: {
    chain: "eth",
    event: "Deposit(address indexed depositor, uint256 amount)",
    requireFinality: true,               // sign only once the source is final
  },

  bindsTo: null,                          // portable — an on-chain fact, not an entitlement

  schema: {
    id: "eth.deposit.v1",
    version: 1,
    fields: [
      { name: "depositor", type: "Uint160" },  // normalized address
      { name: "amount",    type: "Uint64"  },  // wei
      { name: "block",     type: "Uint64"  },  // eth finality anchor
    ],
  },
  build: async (evidence) => {
    const ok = verifyOnChainEvent(evidence);     // YOUR code: finality, contract, log shape
    if (!ok) throw new Error("deposit event rejected");
    const senders = [evidence.depositor];
    if (!senders.includes(evidence.depositor)) throw new Error("unwatched depositor");
    return {
      depositor: normalizeAddress(evidence.depositor),
      amount: evidence.amount,
      block: evidence.finalizedAtSlot,
    };
  },
});

// Same shape, Cardano as its own independent attestor — no `chain` field needed,
// because the policy (which chain) is already part of the attestor's profile.
const cardanoDepositAttestor = thoth.attestor({
  id: "cardano-deposit",
  source: { type: "effectStream" },      // mechanism only

  policy: {
    chain: "cardano",
    event: "Mint '1 <policy>.<asset>' (…)",
    requireFinality: true,               // cardano confirmation-depth / epoch boundary
  },

  bindsTo: null,                          // portable — an on-chain fact, not an entitlement

  schema: {
    id: "cardano.deposit.v1",
    version: 1,
    fields: [
      { name: "depositor", type: "Bytes<32>" }, // normalized address
      { name: "amount",    type: "Uint64"   },  // lovelace
      { name: "block",     type: "Uint64"   },  // cardano finality anchor
    ],
  },
  build: async (evidence) => {
    const ok = verifyOnChainEvent(evidence);     // YOUR code: finality, policy, mint shape
    if (!ok) throw new Error("deposit event rejected");
    const senders = [evidence.depositor];
    if (!senders.includes(evidence.depositor)) throw new Error("unwatched depositor");
    return {
      depositor: normalizeAddress(evidence.depositor),
      amount: evidence.mintAmount,
      block: evidence.finalizedAtSlot,
    };
  },
});
```

Per `source` kind, `policy` is a distinct closed type (a zkFetch policy and an
effectStream policy are different types), since each is canonicalized and compared
on-chain. The knobs above are illustrative, not final.

### Locked config decisions

Decisions settled in the attestor-config sweep; record so they don't get re-litigated.

- **Naming: mechanism, not domain.** There is no "Strava attestor" or "ETH attestor" —
  only a `source` mechanism (`zkFetch` / `effectStream` / `tee`), with a `policy` that
  scopes it (hosts, chain, etc.). Same engine, parametrized. Say "a zkFetch attestor
  scoped to strava.com," never "a Strava attestor."
- **Per-attestor keys.** Each attestor (each policy/`source` vertex) signs with its own
  key — not one key per runner, not one shared across policies. N-of-M only means
  anything if an attacker must compromise N *separate* keys; shared keys make
  "independent" attestors a single point of failure. Cost (more key management) is the
  routine plumbing the library owns. The app pins `key → profile` per attestor; each
  rotates independently.
- **Timestamp: sign Unix, enforce Midnight block time.** The attestor stamps a **Unix
  timestamp** (its own time; the evidence lives on its source chain's clock, and the
  attestor is off-chain — no node dependency). The contract enforces freshness/expiry
  against **Midnight block time converted to Unix**, so both sides share one unit.
  Midnight slots stay an internal node detail, not the frozen claim unit.
- **Request model: pull in v1; push deferred.** v1 attestors are **pull** — the client
  posts evidence, the attestor verifies + signs, returns the signed claim. Push (the
  attestor acting on its own on a schedule/condition and publishing) is deferred until
  the pull path is sane. effectStream attestors currently expose the *latest* signed
  claim on pull; pushing them out is a later step.
- **Failure/rejection: minimal, frozen error contract, not a knob.** The pull path never
  throws an ambiguous error — it returns a typed envelope, so a client can tell *why* it
  failed and whether to fix input, refetch, or wait:

  ```ts
  type AttestResult =
    | { ok: true;  claim: Claim; signature: Signature; profile: ProfileFingerprint }
    | { ok: false; reason: "evidence-rejected" | "verification-failed" | "transient";
        detail?: string; retryAfterMs?: number };
  ```

  - `"evidence-rejected"` — the user's `build` threw (bad input); fix and retry.
  - `"verification-failed"` — the proof failed before `build` (tampered, wrong host).
  - `"transient"` — overloaded/rate-limited/source down; same request may succeed later
    (carry `retryAfterMs`). No retry/backoff knobs in v1 — `pull` clients own their own
    retries, so adding `maxAttempts`/`backoff` is premature. This is a contract the
    library enforces, not per-attestor tunable config.

## The two attestor shapes (the resolved scope)

Both use **independent attestors + N-of-M**; they differ only in where the claimed value
comes from.

1. **Proof-based** — the attestor *derives* the fact from verifiable evidence.
   - zkFetch (web/TLS proof): Strava, GitHub, finance, social APIs.
   - effectStream (cross-chain / chain finality): "deposit happened on ETH", on-chain state.
   - TEE / sensor (hardware attestation quote): "I measured this on this device."
   - **Identity / proof-of-person** (kyc-less sybil resistance, cross-app identity): a zkFetch
     attestor where the fact is *about the caller* (unique human) instead of *about the world*
     — same shape, different schema, not a third shape.

   **Scoping claims (`bindsTo`).** A context-free claim is portable by default, which is right
   for pure facts. It becomes an *amplification vector* only when an app treats the claim as a
   **consumable entitlement** (one reward / access / sybil slot per proof): a single verified
   claim then yields benefits in N apps with zero coordination. Binding the claim to a logical
   app id (→ `bindsTo`) makes N benefits cost N verifications — an opt-in scoping choice, not
   the default. Identity/proof-of-person leans *against* binding (a uniqueness credential is
   meant to be global); consume-gated apps lean towards it.

2. **Corroboration / band** — no proof exists; the client proposes a value and N attestors
   check it within a bound.
   - **Price** (the reference case): client proposes BTC/USD = $104k; each attestor checks that
     number against its own source(s) and attests "valid within margin X" (Pyth-flavored, not a
     copy); N agreeing attestors let the app use the price.
   - Generalizes to any client-claimed value an independent source can bound: credit score,
     stated balance, a self-reported metric.

## Deliberately OUT of scope (decisions, with reasons)

- **Org / 1-of-1 attestation** ("prove you worked at Acme"). Single authority → the registry,
  N-of-M, verifier module, and independent-node story are all redundant. A plain signature
  checked by a Midnight **witness function** does the entire job. Not a library feature.
- **Judgment / voting / adjudication** ("who won?", "is this authentic?"). N attestors co-signing
  an opinion is *voting/consensus*, not *attesting a fact* — a different mechanism with a
  different trust model. Including it muddies what the layer is for. Out.
  - Boundary note: a "who won" case *becomes* shape 2 if a trustworthy reference exists
    (official scoreboard) — then it's corroboration against a source, not judgment.
- **Price oracle absolute truth.** The attestor does not vouch "the price is $104k" (unverifiable,
  mushy). It only vouches a bounded predicate: "|given − my source| ≤ X". The corroboration/band
  shape exists precisely to avoid single-source absolute claims.
- **Aggregation of partial attestations** ("N attestors each cover a piece"). Invalid: if you can
  cheat each attestor on a small part, the whole claim is a cheat. Never composed.
- **Computation results / verifiable compute.** Trusted-execution/zkProof territory, outside an
  attestation layer.

## Trust model & what is per-app, not per-attestor

- **N-of-M threshold** is a per-app pinning choice (already thoth: N is a deploy-time constant),
  **not** baked into an attestor.
- **Which attestors to trust** is likewise per-app: the app pins the keys/registries it trusts
  for a given schema. The library produces signed claims; the app decides who to count.
- Corroboration/band buys *independent corroboration*, not cryptographic strength — the same
  guarantee shape-1 gets from a proof.

## Type/strictness rule

- **No `unknown`, `any`, or `Record<string, unknown>`** in the public type surface. Evidence
  carriers and claim values are **closed** (typed, discriminated, statically mapped). Adding an
  attestor kind is a deliberate type-level change, never a silent escape hatch. Custom logic
  stays type-checked, not boxed into an `any`.

## Implementation stack: Effect internally, plain TS at the boundary

- **Build `@thoth/attestor` on the TypeScript `Effect` library** for the safety it buys at the
  type level from the start: typed error channels, structured concurrency, retries, resource
  management. The **attestor runtime/service may go full Effect** — it's the implementation
  detail that buys correctness, not a surface users touch.
- **The public SDK surface does NOT force Effect on users.** The `attestor()` config, the
  `build` function a user writes, and the `AttestResult` envelope are all **plain TypeScript**
  (the closed, discriminated types above). No user-facing `Effect<…>` types leak into the API.
- The boundary is where internal Effect errors are mapped to the plain `AttestResult` reasons
  (`evidence-rejected` / `verification-failed` / `transient`) — so safety lives inside, and
  consumers get a stable, Effect-free contract.

## Request model (push + pull, unified)

> Decision (see Locked config decisions): **pull is v1; push deferred.**

- **Pull**: client posts evidence, attestor verifies + signs, returns `{ claim, signature, ... }`
  (the existing Witness Fitness `POST /attestate` flow). The only model shipped in v1.
- **Push/reactive** *(deferred)*: attestor watches a source and signs when a condition holds or
  on a schedule (effectStream events, daily snapshot). No client round-trip; signed claims are
  published, the client later collects N of them. Requires resolving the *publish target* (where
  signed claims go — feed/stream/directory/webhook) before it can ship.
- The request model is chosen per attestor and rides on the same `build` function shape.

## Open threads (parked, not decided)

- **Price-band mechanics** are the least-settled part: whether attestors repeat each other's
  sources, exact margin representation, how N-of-M over band-checks is encoded in the claim.
  Needs the most future design.
- **Codegen scope** for the Companion Compact module (core coverage: registry / N-of-M verify /
  membership / nullifier / freshness invariant across attestors; per-attestor: claim encoding +
  challenge parity) — decided at the level of "you describe fields, the lib wires them into a
  shared verifier," but the concrete boundary is an implementation step.
- **Contract-side schema binding** (how an app's `#L` derives from a `ClaimSchema`) — an
  implementation/deploy concern, deferred.

## Where the pieces come from

Grounded in Witness Fitness (read this session): notary pipeline
(`packages/notary/src/{index,verify-reclaim,assert,sign,config}.ts`), parity rule
(`docs/ARCHITECTURE.md` §4), assertion schema (`docs/CONTRACT.md` §2), and thoth's existing
design (`docs/ATTESTOR-NETWORK-DESIGN.md`, `docs/PRIVATE-N-OF-M-ATTESTATIONS.md`,
`docs/EXTRACTION.md`). effectStream contributes the cross-chain evidence source
(`@effectstream/sync` + per-chain contract packages).
