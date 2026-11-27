# Adding an attestor kind

A kind is a family of [attestors](../CONTEXT.md#roles), entities that
verify a fact and sign it, which share one [law](../CONTEXT.md#kinds): what
evidence they accept and verify, what policy they enforce, and how they derive
the shared [claim](../CONTEXT.md#the-claim). The claim is the statement they sign and it is kindless; the policy hash stands in for one, and the policy's slot
map gives each value its meaning. Terms follow [`CONTEXT.md`](../CONTEXT.md).

A new kind that signs the standard claim needs no contract change. The contract
knows nothing about kinds. It sees a claim in the fixed
[wire layout](DESIGN.md#wire-order), checks the signatures against its
[registry](../CONTEXT.md#on-chain) and accepts the
claim's `policyHash` only if it is in its sealed set. An app accepts your kind
by sealing your policy's hash (ADR 0002, ADR 0008).

Two kinds ship today. Use the one whose evidence format and source match yours
as the worked example:
[`@txpipe/thoth-zk-tls`](../packages/zk-tls/README.md) verifies signed evidence
from a zkFetch witness — the party that runs the fetch and signs its evidence —
and [`@txpipe/thoth-cardano`](../packages/cardano/README.md) reads a shared
public ledger.

## What you build

| Piece                                                 | Where it runs                        | Built on                                            | Examples                                                   |
| ----------------------------------------------------- | ------------------------------------ | --------------------------------------------------- | ---------------------------------------------------------- |
| Versioned tag                                         | everywhere                           | —                                                   | `zk-fetch@1`, `cardano@1`                                  |
| Policy schema, normalizer and hash                    | shared                               | `policyHashOf` (`@txpipe/thoth-core/claim-context`) | `zkFetchPolicySchema`, `cardanoPolicySchema`               |
| Subject struct and hash                               | shared                               | `subjectHashOf`                                     | `zkFetchSubjectOf`, `cardanoOutputSubjectOf`               |
| Evidence schema                                       | shared                               | zod                                                 | `zkFetchEvidenceSchema`, `cardanoOutputEvidenceSchema`     |
| Observation schema                                    | attestor, after it reads or verifies | zod                                                 | `cardanoOutputObservationSchema`                           |
| Claim derivation                                      | shared                               | `Claim` (`@txpipe/thoth-core/claim`)                | `deriveClaimFromEvidence`, `deriveCardanoClaim`            |
| Definition (`verify`, `message`)                      | attestor                             | `defineAttestor` (`@txpipe/thoth-attestor`)         | `createZkFetchDefinition`, `createCardanoDefinition`       |
| Input limits                                          | attestor                             | zod `.max()`                                        | `ZK_FETCH_DEFAULT_LIMITS`, `CARDANO_LIMITS`                |
| Instance builder                                      | attestor                             | `buildAttestor`                                     | `zkFetchAttestor`, `cardanoAttestor`                       |
| Client                                                | dApp                                 | `@txpipe/thoth-client`                              | `zkFetchClient`, `cardanoClient`                           |
| Claim context binding (when the evidence can bind it) | shared, checked by the attestor      | `claimContextDigestOf`                              | `zkFetchClaimContextDigestOf`, `assertClaimMatchesContext` |

Put shared logic at the package root, so a client-only app never imports
`@txpipe/thoth-attestor`. Give the attestor and the client their own subpath
entries, as `@txpipe/thoth-zk-tls/attestor` and `@txpipe/thoth-cardano/client`
do.

## What a kind must state

A kind is identified by its law: the evidence, policy and claim schemas, the
derivation, the verification and the message. The law's versioned tag is hashed
into every policy hash. Two attestors with the same tag may trust different
witnesses or readers, and the app's
[trusted set](../CONTEXT.md#signing-and-collection) of attestors
decides which ones it accepts.

Describe the kind by five answers:

- **Accepts.** One evidence schema: a locator, a signed payload, a proof, or a
  union of them. The schema is the boundary; anything outside it is refused
  before the costlier checks.
- **Derives.** Which claim fields the verified evidence fixes, which few the
  proposal supplies, and which the law checks. [The claim](#5-the-claim) gives
  the split.
- **Guarantees.** What `verify` enforces: schemas, derivation, policy pins, and
  the signer's key, or the proof's verifier key or root, configured on the
  definition. It cannot enforce that an operator's reader is honest,
  independent or available.
- **Assumes.** What the operator and the app supply: the source, its
  independence, key custody, input limits. Collusion is out of scope (ADR 0003),
  so the app's trusted set is an assumption.
- **Delegates.** The contract enforces the sealed policy and app id, holder,
  window, threshold and [nullifier](../CONTEXT.md#on-chain); the app decides
  ownership and how much finality it needs.

### Evidence shapes

[Evidence](../CONTEXT.md#roles) is what an attestor verifies before it signs. It
can be a [locator](../CONTEXT.md#kinds) that it uses to re-read an observation, a signed payload it checks, or a proof it
verifies. The fact behind it is the [observation](../CONTEXT.md#the-claim). A
kind can combine them: a provider can read its own source and sign the result,
or a proof can carry a signed payload. What matters is what the evidence fixes.

| Evidence                | Fixes                                                                | Cannot fix                                                                 |
| ----------------------- | -------------------------------------------------------------------- | -------------------------------------------------------------------------- |
| Locator and observation | The fact's identity, and the values the instance read                | The reader's honesty or independence; the context; a time the source lacks |
| Signed payload          | The signed fields, and the context if the signer signed it           | Any field outside the signature                                            |
| Proof                   | The statement's fields, and the context if the statement includes it | Any field outside the statement                                            |

An oracle, a TEE or a zkFetch witness produces a signed payload; a Merkle
inclusion proof or a ZK proof against a verifier key is a proof.

### Source assumptions

State what the source can promise. These decide the window, the salt, the
privacy story and finality.

- **Sharing.** Do all attestors read the same fact? A shared deterministic
  source lets them converge on one message. Independent sources may return
  different observations, and then no threshold forms; pin what makes them
  comparable, or aggregate before the claim.
- **Verifiability.** Can the client or a third party check the read? If not, the
  trusted set carries more weight.
- **Time.** Is there a trusted observation time? If not, do not call the window
  the fact's time.
- **Mutability.** Can the fact change or roll back? If so, the app owns
  finality; depth or expiry is policy, not law.
- **Visibility.** Are the values public, private or guessable? That decides
  whether the salt can be public; see [The claim](#5-the-claim).

## 1. Name the law

Pick a versioned tag such as `my-kind@1`. It is the definition's `kind`, and
`policyHashOf` hashes it together with the policy. Bump it when the meaning of
the evidence, policy, claim or message changes. Every existing policy hash then
changes, so no contract accepts an old policy under the new meaning.

## 2. The policy

The policy is what the app requires of one
[attestation](../CONTEXT.md#signing-and-collection): the fixed conditions the fact must meet, and the slot map that says where its values land in the claim. The dApp sends it with each attestation input, and
the attestor enforces it for that input. Never bake an app's policy into an
attestor instance.

- Write a zod schema. Then write a normalizer that fills defaults and sorts or
  deduplicates anything whose order carries no meaning.
- Hash the normalized form: `policyHashOf(law, normalized)`.
  Policies that mean the same thing must hash the same, or two honest
  attestors sign different messages and never reach the threshold together.
- Map each fact to one slot: numeric facts fill the numeric slots `0..V-1`,
  byte facts fill the byte slots `V..V+W-1`. Declare each slot index and each
  fact once. Check that every slot fits the claim's counts and its fact's
  region before you derive or sign.
- If the evidence carries strings, each slot also declares how its string
  becomes a value. `int` or `float` feeds a numeric slot; `bytes`, `hex` and
  `base64` fill a 32-byte slot, as the
  [Byte slot](../CONTEXT.md#the-claim) entry describes (ADR 0010). A value that
  does not fit, or misses a declared `length`, is not certifiable. A variant
  that maps typed fields, as cardano@1 does, skips the parse rule.
- Keep per-operator configuration out of the policy. Which source an attestor
  trusts and how large an input it parses are operator configuration (zkFetch's
  `witnessAddress` and `limits`, a cardano reader's endpoint), not policy. A
  definition that checks the signer's key or the proof's verifier key or root
  takes it as an argument, as [the definition](#6-the-definition) explains; the
  attestor instance takes the limits.
- Pin the hash of one fixed policy to its bytes in a test, as
  `packages/zk-tls/test/claim-context.test.ts` and
  `packages/cardano/test/output/policy.test.ts` do. A change to the canonical
  form then fails loudly.

## 3. The subject

The [subject](../CONTEXT.md#the-claim) is what the claim is about. Model it as a
struct of `Bytes<32>` fields, usually one hash per part, and hash it with
`subjectHashOf([field, …])` in declaration order. The result equals the
circuit's `persistentHash` of that struct. An app that must accept only one
source takes the subject as private input, recomputes the hash in-circuit, and
compares only the fields it cares about (ADR 0001).

Split the subject along what an app may want to pin versus keep private.
zkFetch uses `{ method, host, path, body }`, so an app can pin the host while
the path, which may name an account, stays hidden; cardano@1 uses
`{ networkMagic, txHash, outputIndex, blockHash }`, all public chain data. The
mock's `openAndBindHost` shows the in-circuit side.

Derive the subject from the evidence your attestor trusts — what the signer
signed or what the instance read — never from what the client says it asked
for.

## 4. The evidence

Accept one canonical evidence shape; the zod schema is the trust boundary.
Normalizing third-party output into that shape is the client's job, and the
attestor parses it before it does anything else. Evidence can take one of many shapes:

- **Observation.** The evidence is a locator that names the fact. The attestor
  re-reads from its own source, and the law derives every field that describes
  the fact from that read. The client can choose which fact to attest, and
  supplies the app id, holder and slot counts, but cannot shape the observation
  (ADR 0007, ADR 0014).
- **Signed payload.** The evidence carries the signer's payload and
  signature. Verify it against the pinned key before the costlier checks.
  Anything the signature does not cover is untrusted client input; do not let it
  drive a policy decision.
- **Proof.** The evidence carries the proof and the claim it proves. Verify it
  against the pinned verifier key or root and reject a proof for another claim.

The client never supplies a fact your attestor trusts without checking it
against its own read, the signer's signature, or the pinned proof. App id,
holder and slot counts are not facts; they are the app's choices, and the
contract or trusted set binds them.

## 5. The claim

The claim carries the app id, policy hash, window, subject hash, holder, salt,
present mask, numeric values and byte values. Use `claimSchema(V, W)` for the
schema and `claimToMessage` for `message` (omit `W` for a numeric-only kind).
Every kind fills the same fields; where the evidence changes a rule, the rule
says so.

The split is the trust boundary:

| Field                                                                                | Comes from                  |
| ------------------------------------------------------------------------------------ | --------------------------- |
| `appId`, `holder`, requested counts                                                  | The claim proposal          |
| `windowStart`, `windowEnd`, `subjectHash`, `salt`, `values`, `byteValues`, `present` | The verified evidence       |
| `version`, `policyHash`                                                              | The law and policy, checked |

For a signed payload the window is proposed and checked against the signer's
observation; where the evidence fixes it, derive it and refuse a different
proposal.

- `policyHash` is your policy hash and `subjectHash` is your subject hash.
- `windowStart` and `windowEnd` are when the observation happened: the signer's
  observation for a signed payload, the observation's own time otherwise. Your
  evidence defines that time (see
  [What a kind must state](#what-a-kind-must-state)). Where the evidence binds
  the window, take the client's proposal and check the observation falls inside;
  otherwise derive it and refuse a different proposal. Both bounds are `Uint<32>`
  Unix seconds.
- `values` are `Uint<64>`, positional, one per numeric slot of the policy's slot
  map. The `present` mask marks which slots were measured: set `present[i]` for
  every measured slot, even when its value is zero. An unmeasured slot is
  `present[i] = false` with value `0`; the contract rejects anything else. Do not
  guess a value you could not read. `claimSchema` rejects a value, window bound
  or version that is negative, fractional, an unsafe integer `number`, or too
  large for its contract type.
- `byteValues` are 32-byte values (identifiers, strings), positional, one per
  byte slot. If your model parses strings, the policy's byte rule canonicalizes
  the disclosed string into the 32-byte slot, zero-padding shorter values; a
  value that does not fit is not certifiable and its slot stays unpresent. Your
  claim carries one flag per byte slot (`present[V + i]`); the contract's `Claim`
  and the nullifier use the split shape in the [wire order](DESIGN.md#wire-order). So a
  dApp returns `toContractClaim(claim)` (from `@txpipe/thoth-core/claim`) from
  `getAttestationWitness`, never your claim itself, even with `W = 0`, whose
  empty `bytePresent`/`byteHalves` the contract still requires.
- `appId` and `holder` come from the claim proposal. The holder is a per-claim
  commitment, not an identity; the contract checks it against the caller's
  secret and checks `appId` against the app id it seals.
- `salt` is a 32-byte value hashed into the nullifier, the public hash of the
  observation identity. It stops one observation from minting many claims:
  derive it from the evidence, refuse a proposal whose salt differs, and every
  attestor derives the same salt from its own evidence. It is public when the
  values are public chain data (ADR 0014). When the values are secret or
  guessable the salt must be secret and hard to guess (ADR 0012): a signed
  payload can carry one because the signer binds it, while a kind whose instance
  reads the fact must derive one from the read, and if the values are guessable
  that needs a secret the attestor set shares, which this repo does not yet
  design for that case. A public salt reveals the fact through the nullifier,
  and so through the claims vault, which the nullifier keys (ADR 0016).

### Binding the claim context

Binding belongs to the evidence format, not the trust label. The
[claim context](../CONTEXT.md#the-claim) is the shared part of one claim: policy
hash, subject hash, holder and window. Where the evidence has a signer, have it
sign the digest that `claimContextDigestOf` (`@txpipe/thoth-core/claim-context`)
computes from that context, and refuse a proposal
whose holder or window gives another digest (ADR 0011). zkFetch signs it into
the witness's context (`assertClaimMatchesContext`).

A signed payload binds the context only if the signer signs it; a proof binds it
only if the statement includes it; a locator cannot bind it. A kind that reads a
shared public fact through a locator does not need it: the fact and window are
fixed by the read, and the nullifier rejects a second holder (ADR 0014). A
private source that the instance reads needs its own answer for binding and for
salt secrecy; this guide does not cover that case.

The claim does not commit to the evidence (ADR 0007). Everything the contract
or app must rely on has to be a field of the claim, which the signed message
commits to: `version` and `holder` directly, every other field through the
nullifier (ADR 0015).

## 6. The definition

`defineAttestor({ kind, policy, evidence, claim, verify, message })` is the
keyless, shareable law. `verify` receives parsed input and throws to reject.
Validate that `present` has one flag per value slot (`values` plus `byteValues`)
and that every policy slot fits within the requested numeric and byte counts and
targets the matching region before the costlier checks. Then:

1. check the signer's key, or the proof's verifier key or root, configured on
   the definition;
2. check the evidence itself: verify the signature, verify the proof, or check
   the observation against the locator;
3. check the evidence against the policy;
4. check the window: where the evidence binds it, that the observation falls
   inside; where the evidence fixes it, that the proposal matches it;
5. check that the proposed `subjectHash` is the one of what the evidence shows;
6. check that the proposed salt is the one the evidence fixes, and where the
   evidence binds the claim context, that the context digest covers the
   proposal's holder and window;
7. check that the proposed values, byte values, and `present` say exactly what
   the evidence showed.

Take the trust anchors as arguments of the function that creates the definition
as `createZkFetchDefinition({ witnessAddress })` does. Then `verify` checks them, so
an operator who pairs the definition with `buildAttestor` keeps them. A kind
whose instance reads the fact has no key or root to check: its instance's `read`
is the assumption, and the app's trusted set is what makes it acceptable.

`message` is `claimToMessage(claim)`: seven fields, the claim's version, its
layout, its nullifier (`nullifierOf(claim)`) and its holder
([wire order](DESIGN.md#wire-order)). Both functions come from
`@txpipe/thoth-core/claim` and need no key. A kind that needs a different
message shape can return another type, but then it needs its own contract
module.

## 7. The instance

`buildAttestor({ id, definition, keyPair, attest })` pairs the law with a key.
In your `attest`:

- parse every input with the definition's schemas, capped to the instance's
  input limits. The attestor serves untrusted callers, so cap every array and
  string before any element is parsed, or a request with millions of slots
  costs you a hash over millions of fields. zkFetch takes the operator's
  `limits` and parses with `zkFetchSchemasWithin(limits)`;
- run `definition.verify`;
- derive the claim yourself from the verified evidence and sign that, not the
  proposal. Take `appId`, `holder` and the requested numeric and byte counts
  from the proposal; take the window from it only when the evidence binds it,
  and derive the salt, every value and present flag;
- sign `definition.message(claim)` and return the claim, message, public key
  and signature.

The [`@txpipe/thoth-attestor` README](../packages/attestor/README.md#usage) signs the
parsed proposal to stay short; a real kind signs the claim it derived, as
`zkFetchAttestor` does.

The instance has no registry slot
([why](../packages/attestor/README.md#design-decisions)) and no fixed slot
counts, so one instance and signing key can serve apps with different claim
layouts. Each consuming contract enforces its own fixed `#V` and `#B`.

Infer the requested counts from `claim.values.length` and
`claim.byteValues.length`, as `zkFetchAttestor` does. Derive the authoritative
claim at those counts, filling unused positions with `present = false` and a
zero value. The dApp client configures its counts for the consuming contract;
the attestor instance needs no `valueSlots`/`byteSlots` field.

## 8. The client

The client runs on the user's machine and builds on `@txpipe/thoth-client` (see its
[Usage](../packages/client/README.md#usage)):

- Take a [`TrustedSet`](../CONTEXT.md#signing-and-collection) built by
  `buildTrustedSet`: the app's pinned attestors, each with the
  [registry slot](../CONTEXT.md#signing-and-collection) it occupies in the
  contract.
- Supply an `AttestorTransport` that sends the raw input and decodes the reply
  into a typed `Attestation`.
- Derive the expected claim from the evidence yourself. Then vet every reply
  with `resolveAttestation({ trusted, member, attestation, verifier,
  expectedClaim })`, using `jubjubVerifier` from `@txpipe/thoth-client/jubjub`.
- Group the replies by exact message. Place each signature at its member's
  `registryIndex`, never by reply order.
- Keep request secrets on the user's machine. The attestors see evidence, not
  credentials.

Fix the holder before you collect: `holderCommitmentOf(secret)` with a fresh
32-byte secret per claim. Only the commitment leaves the machine; the secret
reaches the contract only as private input (ADR 0004).

Where the evidence binds the window, fix it before you collect and have the
producer bind it. Where the observation fixes it, derive it and propose that;
the attestor checks it again and refuses a different one.

## 9. Accepting the kind in an app

- Seal the policy's hash into the contract's `policyHashes` in the constructor.
  One contract can accept several kinds by sealing several hashes.
- Pin the operators' public keys in the registry. Every attestor in one trusted
  set must run the same law and be sent the same policy, or their messages differ and
  never count together.
- Bind the source in the app's own circuit if the app needs it ([the subject](#3-the-subject)).

## Tests

- **Subject parity.** Check `subjectHashOf` against the compiled circuit's
  `persistentHash` of your subject struct, as
  `packages/contracts/test/subject-parity.test.ts` does. Add the struct to the
  mock contract if its shape is new.
- **Policy hash bytes.** Pin one policy to its hash; check that equivalent
  policies hash the same and a changed one does not.
- **Law.** Every `verify` step rejects its own mutation. The instance signs
  the claim it derived, not the one proposed.
- **Acceptance.** Run the path end to end against the simulator, as
  `packages/contracts/test/acceptance.test.ts` does for a signed payload
  and `packages/contracts/test/acceptance-cardano.test.ts` for a kind that
  reads its own source: honest claim accepted and opened by its
  `nullifierOf(claim)`, each signed field mutated and rejected, and a replay
  refused by the nullifier (the generic suite is
  `packages/contracts/test/attestation.test.ts`). Where the evidence binds the
  holder, also check that the attestors refuse the replay, as
  `acceptance.test.ts` does.

## Packaging

A new kind is a new package under `packages/<kind>`. Add it to the root
`package.json` `workspaces`, and to the build-first chain of the root `types`
script if another workspace imports it (see
[CONTRIBUTING.md](../CONTRIBUTING.md#commands)). Pin
`@midnight-ntwrk/compact-runtime` to the same version as the other packages.
