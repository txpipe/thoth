# Thoth

Thoth turns an off-chain fact into a claim a Midnight contract can predicate over, without revealing the fact. The terms below are the vocabulary for that flow.

## Language

### Roles

**Attestor**:
An entity that verifies evidence under a policy and signs a claim if satisfied. Its signature is the attestation.
_Avoid_: Notary, oracle, signer.

**Witness**:
The entity that runs the fetch and signs the evidence behind a claim. Each attestor trusts one witness.
_Avoid_: Prover, node.

**Prover**:
The client-side component that obtains evidence from a witness.
_Avoid_: Witness, attestor.

### The claim

**Claim**:
The canonical statement of what was observed, and the thing attestors sign. It carries the policy hash, the subject hash, the holder, a nonce, an observation window, and the measured values.
_Avoid_: Assertion, statement.

**Policy**:
The rules an attestor enforced to produce an attestation, for example which hosts it accepts. The claim commits to it by hash.
_Avoid_: Rules, config.

**Kind**:
The off-chain law an attestor implements, such as zkFetch. It never appears on-chain; the policy hash stands in for it.
_Avoid_: Type, scheme, provider.

**policyHash**:
A hash of the policy the attestors enforced. The contract seals the hash it accepts and rejects any other, so a requester cannot substitute a laxer policy.
_Avoid_: policyDigest, rulesHash.

**subjectHash**:
A hash of what the claim is about: the request for zkFetch, the event for an event kind. The app checks it privately.
_Avoid_: requestBinding, evidenceHash, metaHash.

**Holder**:
A per-claim commitment, not a user id. Only the owner of that claim’s secret can vault it. The layer does not promise that two claims share a holder.
_Avoid_: Owner, user, account, identity.

**Intent**:
The shared context for one attestation: policy hash, subject hash, holder, nonce, and window. Every witness signs the same intent, so every attestor derives the same claim.
_Avoid_: Request, session.

**present**:
The mask marking which value slots were measured. `present[i]` true means slot i was measured, even when its value is zero.
_Avoid_: Flags, mask.

**Values**:
The measured numbers of a claim, positional. Zero is a valid measured value; read `present` to know whether a slot was filled.
_Avoid_: Data, payload, slots.

**Observation**:
One attested session: the single fetch or event read the witnesses signed. Unique by construction.
_Avoid_: Request, session.

**Fact**:
The stable subject an observation is about, which could be observed again later, such as an account balance or a given event.
**Window**:
When the attestor observed the claim, not when the underlying fact happened. The contract checks it against its own clock; a fact’s own time travels as a value.
_Avoid_: Timestamp, event time.

### Signing and collection

**Attestation**:
The signed artifact one attestor returns: the claim, the message, the public key, and the signature.
_Avoid_: Proof.

**Attestment**:
The collected N-of-M set for one claim: the shared claim, its message, and one attestation per answered attestor. Not final until the contract accepts it.
_Avoid_: Collection, bundle, proof.

**Message**:
The flat list of field values the attestors sign and the contract rebuilds. Its order is the wire layout.
_Avoid_: Payload, digest.

**Trusted set**:
An app's pinned attestors and the registry slot each answers from.
_Avoid_: Allowlist.

**Trusted member**:
One entry of a trusted set: an attestor's descriptor paired with the registry slot the app assigned it (`TrustedAttestor` in code).
_Avoid_: Pinned attestor, entry.

### On-chain

**Registry**:
The pinned attestor public keys in a contract, sealed at deploy. Signatures are checked positionally against it.
_Avoid_: Trusted set.

**Threshold**:
The N in N-of-M: how many registry keys must sign the same message.
_Avoid_: Quorum, majority.

**Nullifier**:
The marker that stops a nonce from being accepted twice.
_Avoid_: Replay marker.

**Claims vault**:
The store of accepted claims, keyed by a commitment. Claim values are never stored on-chain.
_Avoid_: Vault, storage.
