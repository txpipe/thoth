# Attestors sign the nullifier, and byte values travel whole

Status: accepted

The signed message was a flat vector of fields that split each 32-byte field into two 16-byte halves, so that every byte reached the signature. A circuit holds a `Bytes<32>` as two field elements, byte 31 and bytes 0-30, so cutting it at byte 16 decomposes it byte by byte: each split cost about 13,700 rows, and the five 32-byte header fields took 68,700 of `verifyAttestation`'s 90,600 rows (k = 17 in the test mocks). The contract's claim carried byte values as 16-byte halves for the same reason (ADR 0009), and a predicate paid about 8,700 rows to reassemble one. Meanwhile the contract already hashed every claim field except `holder` and `version` with SHA-256, into the nullifier, to reject replays (ADR 0006, ADR 0012); the nullifier also keys the claims vault ([ADR 0016](0016-claims-vault-keyed-by-the-nullifier.md)).

Attestors now sign seven fields: `[version, V, W, nullifier, holder]`, each 32-byte value as two elements, byte 31, then bytes 0-30 read little-endian. `verifyAttestation` hashes the claim once and uses the nullifier for the signatures, replay and the vault key. The module declares the message as a struct, `SignedMessage { version, v, w, nullifier: Bytes<32>, holder: Bytes<32> }`, and the registry takes the message type as a module parameter, so its Schnorr challenge absorbs the two 32-byte values as the circuit holds them, with no byte sliced. `transientHash` flattens that struct into exactly the seven fields, so attestors sign them as a `Vector<7, Field>` with the runtime's `jubjubSchnorrSign`, and a client verifies them with the runtime's `jubjubSchnorrVerify`. The contract's `Claim` carries each byte value whole, as `Bytes<32>` with one flag per value: the module parameter `#B` (byte halves) becomes `#W` (byte values), and `#K` is gone. The full layout, with the nullifier's preimage, is in the `attestation.compact` header and the docs/DESIGN.md table.

With the claims vault keyed by the nullifier and N named signatures ([ADR 0015](0015-contract-verifies-n-named-signatures.md)), `verifyAttestation` takes 11,233 rows in the numeric mock (`V = 3`, `W = 0`, 2-of-3) and 13,179 in the bytes mock (`W = 1`), both k = 14, and reading a byte value in a predicate is one comparison.

Why the guarantees hold:

- Every claim byte reaches the message. `version` and `holder` are fields of it; a 32-byte value's two elements are below 2^8 and 2^248, both under the field modulus, so they give back all 32 bytes. Every other field reaches it through the nullifier, whose preimage has a fixed width per layout, so equal preimages mean equal fields. Two claims of one layout share a message only through a SHA-256 collision. The contract relies on SHA-256 collision resistance already: `openClaim` returns the observation whose SHA-256 is the vault key, the holder commitment is SHA-256, and source binding compares a `persistentHash`.
- `V` and `W` are in the message. The observation identity is `136 + 9V + 33W` bytes, so two layouts can serialize to the same bytes (`V = 11, W = 0` and `V = 0, W = 3`); the contract writes its own `#V` and `#W`, so a message signed under one layout fails under the other. The sealed app id does not separate layouts: it is the first 32 bytes of every layout's identity, and every contract of one app seals the same one.
- Nothing the signatures bind rests on a transient primitive. The nullifier is a persistent hash; the only Poseidon is the Schnorr challenge, as before.
- The nullifier is unchanged, so it hides the values exactly as before (ADR 0012). A leaked message shows the nullifier, public once the claim is submitted, and the holder commitment, not the salt or any value.
- `@thoth/core` computes the nullifier with standard SHA-256 over the documented bytes, and stays keyless.

Considered options:

- A Poseidon digest of the claim, `transientHash([V, W, claim])`, signed as one field: 11,343 and 13,310 rows, the same k as this encoding at every layout measured (up to 5-of-8 with `V = 8`, `W = 4`). The signatures then bind the claim only as far as Poseidon is collision resistant, and `transientHash` sits in what attestors sign although Midnight may change it at a hard fork. It does not tie the signatures to the observation identity.
- Each 32-byte claim field as its two elements, no hash: no new assumption, but 12,940 and 15,260 rows, and a message that grows with the layout, which every signature's challenge absorbs again: the bytes mock reaches k = 15 at 3-of-5.
- These seven fields through the stdlib verifier, the message a `Vector<7, Field>` built with `slice<1>` and `degradeToTransient`: 11,809 and 13,755 rows. The struct message signs the same fields and saves those conversions, about 290 rows per 32-byte value.
- A dedicated SHA-256 of the whole claim, decoupled from the nullifier: four more SHA-256 blocks, k = 15.
- Halves in the claim: the message needs no slicing, but the holder and subject-hash checks compare against `persistentHash` outputs and pay about 8,700 rows each to reassemble.

Consequences:

- The observation identity is part of the wire format. To sign, an attestor serializes it and hashes it. A change to the `Observation` struct (a field, the order, a width) or to its hash changes what every attestor signs: a coordinated attestor release, and every signature in flight fails. Without this encoding such a change touched the contract alone; with the vault keyed by the nullifier it already re-keys stored claims. The claim's `version` contains it: a new identity takes a new version, which the contract checks and every policy hash commits to.
- The message shows no claim field but the version and the holder. To show a person what is signed, an attestor shows the claim and recomputes its nullifier with standard SHA-256.
- A kind that extends the claim signs its own message the same way, over its own observation identity, or keeps its own encoder.
- Whoever holds a signature, the holder commitment and the claim's nullifier can show that an attestor attested the observation with that public nullifier without showing the salt or the values. Only the client and the attestor hold a signature.
- A contract that imports the registry itself, to call `initRegistry`, imports it with the attestation module's `SignedMessage` as its message type.

Amends ADR 0006 (the attestors sign the observation identity's hash) and ADR 0009 (a byte value is no longer split into halves, in the message or in the contract's claim).
