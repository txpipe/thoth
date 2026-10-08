# Thoth

Thoth turns an off-chain fact into a claim a Midnight contract can predicate over, without revealing the fact. The terms below are the vocabulary for that flow.

## Language

### Roles

**Attestor**:
An entity that verifies evidence under a policy and signs a claim if satisfied. Its signature is the attestation.
_Avoid_: Notary, oracle, signer.

**Witness**:
The entity that runs the fetch and signs the evidence behind a claim. Each attestor trusts one witness. Not a Compact `witness` function, which is how the contract reads private input.
_Avoid_: Prover, node.

**Prover**:
The client-side component that obtains evidence from a witness.
_Avoid_: Witness, attestor.

### Kinds

**Kind**:
A family of attestors that share one law, such as zkFetch. It never appears on-chain; the policy hash stands in for it.
_Avoid_: Type, scheme, provider.

**Law**:
What a kind implements: its policy, evidence and claim schemas, the `verify` step, and the `message` encoding. Keyless and shareable; many attestor instances run one law. Its versioned tag, such as `zk-fetch@1`, is the kind identifier and is hashed into every policy hash.
_Avoid_: Driver, plugin.

### The claim

**Claim**:
The canonical statement of what was observed, and the thing attestors sign. It carries the version, the app id, the policy hash, the observation window, the subject hash, the holder, the present mask, and the measured values. It carries no nonce and no kind.
_Avoid_: Assertion, statement.

**Version**:
The claim's wire version, `1`. It stays `1` until a layout is deployed.
_Avoid_: Schema id.

**App id**:
The 32 bytes naming the app a claim is for. Signed into the claim and into the observation identity. The module does not check it; an app that must refuse another app's claims compares it in its own predicate.
_Avoid_: Scope, contract id.

**Policy**:
The rules an attestor enforced to produce an attestation, for example which hosts it accepts. The claim commits to it by hash.
_Avoid_: Rules, config.

**Disclosure rules**:
The zkFetch policy's response patterns and reveal whitelist (`responseMatches` and `responseRedactions`): the exact extraction the witness executed and signed into the claim. The attestor requires the signed rules to equal the policy's, and the policy hash commits to them, so a claim slot cannot be pointed at a different field than the policy intends.
_Avoid_: Extraction plan, reveal plan.

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

**Window**:
When the attestor observed the claim, not when the underlying fact happened. The contract checks it against its own clock; a fact's own time travels as a value.
_Avoid_: Timestamp, event time.

**present**:
The mask marking which value slots were measured. `present[i]` true means slot i was measured, even when its value is zero. An absent slot must carry zero.
_Avoid_: Valid, filled.

**Values**:
The measured numbers of a claim, one per value slot. Zero is a valid measured value; read `present` to know whether a slot was measured. What each slot means is the policy's slot map, not the claim's.
_Avoid_: Data, payload.

**Claim proposal**:
The claim the client sends an attestor with the evidence. The attestor signs the claim it derives itself, taking only the app id, holder, window and requested value-slot count from the proposal.
_Avoid_: Draft, request.

**Claim context**:
The shared part of one attestation: policy hash, subject hash, holder, and window. Every attestor given the same claim context and the same observation derives the same claim. `claimContextDigestOf` hashes it for a witness to sign. The app id is not part of it: no witness signs it, and each attestor takes it from the claim proposal.
_Avoid_: Intent, request, session.

**Observation**:
One attested session: the single fetch or event read the witnesses signed. Unique by construction.
_Avoid_: Request, session.

**Observation identity**:
The fields that make an observation unique: app id, policy hash, subject hash, window, values, and present. It excludes holder and version.
_Avoid_: Claim id, nonce.

**Fact**:
The stable subject an observation is about, which could be observed again later, such as an account balance or a given event.
_Avoid_: Truth, data.

### Signing and collection

**Message**:
The flat list of field values the attestors sign and the contract rebuilds.
_Avoid_: Payload, digest.

**Wire layout**:
The order and encoding of the message's fields, `K = 2*V + 11` of them. `buildMessage` in `attestation.compact` defines it and `claimToMessage` mirrors it.
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
The hash of the observation identity. The contract stores it so the same observation is not accepted twice, whatever the holder.
_Avoid_: Replay marker, nonce.

**Claims vault**:
The store of accepted claims, keyed by a commitment. Claim values are never stored on-chain.
_Avoid_: Vault, storage.

## Relationships

- A **kind** has one **law**; many **attestors** run it, each trusting its own **witness**.
- A **policy** belongs to one law; its **policyHash** is what the contract seals.
- An **observation** produces one **claim**; the **nullifier** keys on its **observation identity**, so a fresh **holder** cannot claim it again.
- An **attestment** is N **attestations** over one **message**, each placed at its **registry slot** from the **trusted set**.
