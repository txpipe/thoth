# Thoth

Thoth turns an off-chain fact into a claim a Midnight contract can predicate over, without revealing the fact. The terms below are the vocabulary for that flow.

## Language

### Roles

**Attestor**:
An entity that verifies evidence under a policy and signs a claim if satisfied. Its signature is the attestation. `Attestor` in code is one deployed instance: a law paired with a signing key.
_Avoid_: Notary, oracle, signer.

**Descriptor**:
The public view of an attestor that a dApp pins: its id, its law and its public key, without the signing key (`AttestorDescriptor` in code).
_Avoid_: Attestor info, handle.

**Witness**:
The entity that runs the fetch and signs the evidence behind a claim. Each attestor trusts one witness. Not a Compact `witness` function, which is how the contract reads private input.
_Avoid_: Prover, node.

**Prover**:
The client-side component that obtains evidence from a witness.
_Avoid_: Witness, attestor.

**Evidence**:
What a prover obtains from a witness and an attestor verifies before signing, such as a zkFetch proof of an HTTPS fetch. The claim does not commit to it (ADR 0007).
_Avoid_: Proof.

**Redaction marker**:
A `*` the prover writes into the TLS transcript in place of a request byte it hides from the witness. The prover chooses which bytes it redacts, and Reclaim compares a `*` in the signed request as equal to a marker, so a signed `*` binds no sent byte.
_Avoid_: Mask, wildcard.

### Kinds

**Kind**:
A family of attestors that share one law, such as zkFetch. It never appears on-chain; the policy hash stands in for it.
_Avoid_: Type, scheme, provider.

**Law**:
What a kind implements: its policy, evidence and claim schemas, the `verify` step, and the `message` encoding. Keyless and shareable; many attestor instances run one law. A law may take operator configuration with no secret in it, such as the witness zkFetch trusts. Its versioned tag, such as `zk-fetch@1`, is the kind identifier and is hashed into every policy hash.
_Avoid_: Driver, plugin.

### The claim

**Claim**:
The canonical statement of what was observed, and the thing attestors sign. It carries the version, the app id, the policy hash, the observation window, the subject hash, the holder, the salt, the present mask, and the measured values (numeric and byte). It carries no nonce and no kind.
_Avoid_: Assertion, statement.

**Version**:
The claim's wire version, `1`. It stays `1` until a layout is deployed.
_Avoid_: Schema id.

**App id**:
The 32 bytes naming the app a claim is for. Signed into the claim and into the observation identity. The contract seals one app id at deploy and rejects a claim for any other.
_Avoid_: Scope, contract id.

**Policy**:
The rules an attestor enforced to produce an attestation, for example which hosts it accepts. The claim commits to it by hash.
_Avoid_: Rules, config.

**Slot map**:
The part of a policy that says which value slot each extracted field fills and the parse rule that turns the field's string into the slot's value (`slots` in a zkFetch policy).
_Avoid_: Schema, field map.

**Disclosure rules**:
The zkFetch policy's response patterns and reveal whitelist (`responseMatches` and `responseRedactions`): the exact extraction the witness executed and signed into the claim. The attestor requires the signed rules to equal the policy's, and the policy hash commits to them, so a claim slot cannot be pointed at a different field than the policy intends.
_Avoid_: Extraction plan, reveal plan.

**Body policy**:
The zkFetch policy's required rule for the signed request body (`bodyPolicy`): `non-empty`, a `{ sha256 }` pin, or `ignored`, which leaves the sent body unbound. The policy hash commits to it, and the subject hashes the signed body. The modes and when to use each are in [Body policy](packages/zk-tls/docs/dapp-integration.md#body-policy).
_Avoid_: emptyBody, requestBody.

**policyHash**:
A hash of the policy the attestors enforced, tagged with the kind's law and the wire version. The contract seals the set of hashes it accepts and rejects any other, so a requester cannot substitute a laxer policy.
_Avoid_: policyDigest, rulesHash.

**Subject**:
What a claim is about, as a struct of 32-byte fields: the request for zkFetch, the event for an event kind.
_Avoid_: Request, source.

**subjectHash**:
The circuit hash of the subject. The app recomputes it in-circuit from private subject fields when it needs to bind the source.
_Avoid_: requestBinding, evidenceHash, metaHash.

**Holder**:
A per-claim commitment, not a user id. Only the owner of that claim's secret can vault it. The layer does not promise that two claims share a holder.
_Avoid_: Owner, user, account, identity.

**Salt**:
A secret 32-byte value the claim carries and the nullifier hashes, so the nullifier cannot confirm a guessed value. The kind fixes it from the evidence, so the client cannot change it without new evidence. zkFetch uses the claim context digest, so the salt follows the holder and window the client binds before proving. It never appears on-chain (ADR 0012).
_Avoid_: Nonce, randomness.

**Window**:
When the attestor's witness observed, in Unix seconds, not when the underlying fact happened. It is not the exact fetch time: a zkFetch witness's observation time (`timestampS`) comes from the request, and Reclaim rejects it only if it is more than 10 minutes in the future, with no lower bound. So the window shows the fetch happened no earlier than about 10 minutes before `windowStart`. Freshness still holds on-chain, because post-dating is capped. The contract checks the window against its own clock; a fact's own time travels as a value (ADR 0005).
_Avoid_: Timestamp, event time.

**present**:
The mask marking which value slots were measured, one flag per slot, numeric slots first and byte slots after. `present[i]` true means slot i was measured, even when its value is zero. An absent slot must carry zero.
_Avoid_: Valid, filled.

**Values**:
The measured values of a claim, one per value slot: numbers in the numeric slots, fixed-width byte strings in the byte slots. Zero is a valid measured value; read `present` to know whether a slot was measured. What each slot means is the policy's slot map.
_Avoid_: Data, payload.

**Byte slot**:
A value slot carrying a 32-byte string, for facts that are not numbers, such as identifiers (ADR 0009). A parse rule canonicalizes a source's string into the slot, zero-padded: `bytes` keeps its UTF-8 bytes, `hex` and `base64` decode it, and an optional `length` pins the exact byte count. Decoding folds only representations that carry no data, such as hex case; separators and whitespace are data (ADR 0010). The slot is exactly its bytes, and equality is byte equality. In the message and the contract's `Claim` it occupies two 16-byte byte halves (`byteHalves`), which a predicate reassembles in-circuit; the wire layout places them.
_Avoid_: Blob, string slot.

**Claim proposal**:
The claim the client sends an attestor with the evidence. The attestor signs the claim it derives itself, taking only the app id, holder, window and the requested numeric and byte value-slot counts from the proposal, and refuses a proposal whose salt differs from the one it derives.
_Avoid_: Draft, request.

**Claim context**:
The shared part of one attestation: policy hash, subject hash, holder, and window. Every attestor given the same claim context and the same observation derives the same claim. `claimContextDigestOf` hashes it. The witness signs that digest with its evidence and the attestor recomputes it from the claim proposal, so evidence signed for one holder and window yields no claim for another (ADR 0011). The app id is not part of it: each attestor takes the app id from the claim proposal.
_Avoid_: Intent, request, session.

**Observation**:
One attested session: the single fetch or event read the witnesses signed. Unique by construction.
_Avoid_: Request, session.

**Observation identity**:
The fields that make an observation unique: app id, policy hash, subject hash, salt, window, numeric values, byte values, and present. It does not include holder or version directly; the holder reaches it only through the kind's salt.
_Avoid_: Claim id, nonce.

**Fact**:
The stable subject an observation is about, which could be observed again later, such as an account balance or a given event.
_Avoid_: Truth, data.

**Predicate**:
The app's own circuit logic over an accepted claim, such as "at least 100 stars". Attestors certify the fact; the predicate decides what the app does with it.
_Avoid_: Condition.

### Signing and collection

**Message**:
The flat list of field values the attestors sign and the contract rebuilds.
_Avoid_: Payload, digest.

**Wire layout**:
The order and encoding of the message's fields. The [`attestation.compact`](packages/contracts/attestation.compact) header and the table in [docs/DESIGN.md](docs/DESIGN.md#wire-order) write it out; `buildMessage` defines it and `claimToMessage` mirrors it.
_Avoid_: Format, serialization.

**Attestation**:
The signed artifact one attestor returns: the claim, the message, the public key, and the signature.
_Avoid_: Proof.

**Attestment**:
The collected N-of-M set for one claim: the shared claim, its message, and one attestation per answered attestor, each at its registry slot. Not final until the contract accepts it.
_Avoid_: Collection, bundle, proof.

**Trusted set**:
An app's pinned attestors, each with the registry slot the app assigned it.
_Avoid_: Allowlist.

**Trusted member**:
One entry of a trusted set: an attestor's descriptor paired with the registry slot the app assigned it (`TrustedAttestor` in code).
_Avoid_: Pinned attestor, entry.

**Registry slot**:
The position of an attestor's key in the app's registry, `registryIndex` in code. The app assigns it; the attestor does not know it. Signatures are placed by it and by nothing else.
_Avoid_: Attestor index, rank.

**Collection options**:
What the client fixes before collecting: the holder, the window, a local deadline, the threshold, and which attestors to try (`ZkFetchThresholdOptions` in code). Only the holder and window reach the signed claim.
_Avoid_: Intent, claim context, request.

### On-chain

**Registry**:
The pinned attestor public keys in a contract, sealed at deploy. Signatures are checked positionally against it.
_Avoid_: Trusted set.

**Threshold**:
The N in N-of-M: how many registry keys must sign the same message.
_Avoid_: Quorum, majority.

**Nullifier**:
The hash of the observation identity. The contract stores it so the same observation is not accepted twice. It is public, but it hashes the secret salt, so a guess at a claim's values cannot be confirmed by recomputing it.
_Avoid_: Replay marker, nonce.

**Claims vault**:
The store of accepted claims, keyed by a commitment. It does not store claim values on-chain.
_Avoid_: Vault, storage.

## Relationships

- A **kind** has one **law**; many **attestors** run it, each trusting its own **witness**.
- A **policy** belongs to one law; its **policyHash** is what the contract seals.
- An **observation** produces one **claim** for each app id and slot count; the **nullifier** keys on its **observation identity**, so the same claim cannot be accepted twice. The evidence binds the **claim context**, so a fresh **holder** needs a new observation; where the **salt** follows the holder, that observation gets a new nullifier even for the same fact ([details](packages/contracts/README.md#guarantees-and-limits)).
- An **attestment** is N **attestations** over one **message**, each placed at its **registry slot** from the **trusted set**.
