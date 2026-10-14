# Adding an attestor kind

A kind is a family of attestors that share one law: how they read evidence,
what policy they enforce, and which claim they sign. zkFetch
([`@thoth/zk-tls`](../packages/zk-tls/README.md)) is the reference kind; this
guide names its pieces as the example for each step. Terms follow
[`CONTEXT.md`](../CONTEXT.md).

A new kind that signs the standard claim needs **no contract change**. The
contract knows nothing about kinds.
It sees a claim in the fixed [wire layout](DESIGN.md#the-claim), checks the
signatures against its registry, and accepts the claim's `policyHash` only if
it is in its sealed set. An app accepts your kind by sealing your policy's
hash (ADR 0002, ADR 0008).

## What you build

| Piece | Where it runs | Built on | zkFetch example |
|-------|---------------|----------|-----------------|
| Law tag | everywhere | — | `ZK_FETCH_LAW = 'zk-fetch@1'` |
| Policy schema, normalizer and hash | shared | `policyHashOf` (`@thoth/core/claim-context`) | `zkFetchPolicySchema`, `normalizePolicy`, `zkFetchPolicyHashOf` |
| Subject struct and hash | shared | `subjectHashOf` | `zkFetchSubjectOf`, `zkFetchSubjectHashOf` |
| Evidence schema | shared | zod | `zkFetchEvidenceSchema` |
| Claim derivation | shared | `Claim` (`@thoth/core/claim`) | `deriveClaimFromEvidence` |
| Definition (`verify`, `message`) | attestor | `defineAttestor` (`@thoth/attestor`) | `createZkFetchDefinition` |
| Instance builder | attestor | `buildAttestor` | `zkFetchAttestor` |
| Client | dApp | `@thoth/client` | `zkFetchClient` |

Put shared logic at the package root, so a client-only app never imports the
attestor host. Give the attestor and the client their own subpath entries, as
`@thoth/zk-tls/attestor` and `@thoth/zk-tls/client` do.

## 1. Name the law

Pick a versioned tag such as `my-kind@1`. It is the definition's `kind`, and
`policyHashOf` hashes it together with the policy. Bump it when the meaning of
a policy changes. Every existing policy hash then changes, so no contract
accepts an old policy under the new meaning.

## 2. The policy

The policy is what the app requires of one attestation, for example which hosts
zkFetch accepts and which disclosed field lands in which value slot. The dApp
sends it with each attestation input, and the attestor enforces it for that input.
Never bake an app's policy into an attestor instance.

- Write a zod schema. Then write a normalizer that fills defaults and sorts or
  deduplicates anything whose order carries no meaning.
- Hash the normalized form: `policyHashOf(law, normalized, claimVersion)`.
  Policies that mean the same thing must hash the same, or two honest
  attestors sign different messages and never reach the threshold together.
- Each slot declares how its disclosed string is interpreted: `int` or `float`
  feeds a numeric slot, `bytes` keeps the string's UTF-8 bytes zero-padded to 32
  in a byte slot (a string longer than 32 bytes is not certifiable). Numeric
  rules must target numeric slots; `bytes` must target byte slots.
- Keep per-operator trust anchors out of the policy. Which witness an attestor
  trusts is instance configuration (zkFetch's `witnessAddress`), not law.
- Pin the hash of one fixed policy to its bytes in a test, as
  `packages/zk-tls/test/claim-context.test.ts` does. A change to the canonical
  form then fails loudly.

## 3. The subject

The subject is what the claim is about. Model it as a struct of `Bytes<32>`
fields, usually one hash per part, and hash it with
`subjectHashOf([field, …])` in declaration order. The result equals the
circuit's `persistentHash` of that struct. An app that must accept only one
source takes the subject as private input, recomputes the hash in-circuit, and
compares only the fields it cares about (ADR 0001).

Split the subject along what an app may want to pin versus keep private.
zkFetch uses `{ method, host, path, body }`, so an app can pin the host while
the path, which may name an account, stays hidden. The mock's
`openAndBindHost` shows the in-circuit side.

Derive the subject from what the evidence signed, never from what the client
says it asked for.

## 4. The evidence

Accept one canonical evidence shape; the zod schema is the trust boundary.
Normalizing third-party output into that shape is the client's job. Anything
the evidence's own signature does not cover is untrusted client input. Do not
let it drive a policy decision.

## 5. The claim

Use the canonical claim: `claimSchema(V, W)` for the schema and
`claimToMessage` for `message` (omit `W` for a numeric-only kind). Your kind decides only the header fields that come from the evidence
and the values:

- `policyHash` is your policy hash and `subjectHash` is your subject hash.
- `windowStart` and `windowEnd` are the window the client proposed. Sign it
  only if your source's observation falls inside it. When the
  fact itself happened, such as a block height or event time, is a value, not
  the window (ADR 0005).
- `values` are `Uint<64>`, positional, one per numeric slot of the policy's slot
  map. Set `present[i]` for every measured slot, even when its value is zero. An
  unmeasured slot is `present[i] = false` with value `0`; the contract rejects
  anything else. Do not guess a value you could not read.
- `byteValues` are 32-byte values (identifiers, strings), positional, one per
  byte slot. Canonicalize a disclosed string by zero-padding its UTF-8 bytes to
  32; a longer string is not certifiable and its slot stays unpresent. The kind
  layer carries one flag per byte slot (`present[V + i]`); `claimToMessage` and
  the contract split each value into two adjacent 16-byte halves and repeat the
  flag on both halves.
- `appId` and `holder` come from the claim proposal. The attestor signs them
  but cannot check them. The contract checks `holder` against the caller's
  secret; `appId` is compared by the app's own predicate, not by the module.

The claim does not commit to the evidence (ADR 0007). Everything the contract
or app must rely on has to be a field of the signed message.

## 6. The definition

`defineAttestor({ kind, policy, evidence, claim, verify, message })` is the
keyless, shareable law. `verify` receives parsed input and throws to reject.
Validate that `present` has one flag per value slot (`values` plus `byteValues`)
and that every policy slot fits within the requested numeric and byte counts and
targets the matching region before proof verification. Then:

1. verify the evidence's own signature;
2. check the evidence against the policy;
3. check that the observation falls inside the proposed window;
4. check that the proposed `subjectHash` is the one of what the evidence signed;
5. check that the proposed values, byte values, and `present` say exactly what
   the evidence showed.

`message` is `claimToMessage(claim)`. A kind that needs a different message
shape can return another type, but then it needs its own contract module.

## 7. The instance

`buildAttestor({ id, definition, keyPair, attest })` pairs the law with a key.
In your `attest`:

- parse every input with the definition's schemas;
- run `definition.verify`;
- check per-instance trust anchors, such as "the evidence was signed by *my*
  witness";
- **derive the claim yourself** from the verified evidence and sign that, not
  the proposal. Take `appId`, `holder`, the window and the requested count from
  the proposal, but derive every value and present flag;
- sign `definition.message(claim)` and return the claim, message, public key
  and signature.

The instance has no registry slot or fixed value-slot count, so one instance
and signing key can serve apps with different claim layouts. Each consuming
contract enforces its own fixed `#V`.

Infer the requested count from `claim.values.length`, as `zkFetchAttestor`
does. Derive the authoritative claim at that count, filling unused positions
with `present = false` and `value = 0`. The dApp client configures its count
for the consuming contract; the attestor instance needs no `valueSlots` field.

## 8. The client

The client runs on the user's machine and builds on `@thoth/client` (see its
README, "For kind SDK authors"):

- Take a `TrustedSet` built by `buildTrustedSet`. The app assigns each
  attestor's registry slot there.
- Supply an `AttestorTransport` that sends the raw input and decodes the reply
  into a typed `Attestation`.
- Derive the expected claim from the evidence yourself. Then vet every reply
  with `resolveAttestation({ trusted, member, attestation, verifier,
  expectedClaim })`, using `jubjubVerifier` from `@thoth/client/jubjub`.
- Group the replies by exact message. Place each signature at its member's
  `registryIndex`, never by reply order.
- Keep request secrets on the user's machine. The attestors see evidence, not
  credentials.

The holder is `holderCommitmentOf(secret)` with a fresh 32-byte secret per
claim. Only the commitment leaves the machine; the secret reaches the contract only
as private input (ADR 0004).

## 9. Accepting the kind in an app

- Seal the policy's hash into the contract's `policyHashes` in the constructor.
  One contract can accept several kinds by sealing several hashes.
- Pin the operators' public keys in the registry. Every attestor in one trusted
  set must run the same law and be sent the same policy, or their messages differ and
  never count together.
- Bind the source in the app's own circuit if the app needs it (step 3).

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
  `packages/contracts/test/acceptance.test.ts` does for zkFetch: honest claim
  accepted, each signed field mutated and rejected.

## Packaging

A new kind is a new package under `packages/<kind>`. Add it to the root
`package.json` `workspaces`, and to the build-first chain of the root `types`
script if another workspace imports it (see `AGENTS.md`, "Stale `dist/`
footgun"). Pin `@midnight-ntwrk/compact-runtime` to the same version as the
other packages.
