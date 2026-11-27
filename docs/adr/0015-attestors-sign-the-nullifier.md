# Attestors sign the nullifier

Status: accepted

Attestors used to sign the claim as a flat list of fields, with each 32-byte field cut into two 16-byte halves. A circuit holds 32 bytes as bytes 0-30 in one field plus byte 31, so every cut at byte 16 decomposes the value byte by byte: about 13,700 rows per field, five fields, three quarters of `verifyAttestation` (90,610 rows, `k = 17`). The circuit then hashed nearly the same fields again for the nullifier.

Attestors now sign seven fields: the claim's `version`, the layout (`V` and `B`), and the nullifier and the `holder`. A 32-byte value is two fields, byte 31 and then bytes 0-30 read little-endian, which is how the circuit already holds it; both fit a field without wraparound, so the pair is injective. `version` and `holder` reach the signature directly, and every other claim field reaches it through the nullifier, the SHA-256 of the observation identity that `verifyAttestation` computes anyway for replay. The registry verifies the seven fields with the standard library's `jubjubSchnorrVerify`, and the message length is no longer a module parameter. `verifyAttestation` falls to about 23,100 rows on the numeric mock and 26,900 on the bytes mock (`k = 15`). Issue #309 has the measurements.

The message signs the layout because the nullifier hashes a plain concatenation of the identity, 136 + 9V + 17B bytes. Two layouts can serialize two claims to the same bytes (`V = 34, B = 0` and `V = 0, B = 18`), and so to the same nullifier. The sealed app id does not separate them, because every contract of one app seals the same one.

Considered options:

- Sign a Poseidon digest of the claim (one field). Same cost, but the signed message then rests on Poseidon collision resistance, while replay protection and the vault already rest on SHA-256.
- Sign each field as native field elements (limbs). No new assumption, but 1,600 to 4,300 more rows, and it reaches `k = 15` first as the layout grows.
- Sign a separate SHA-256 of the whole claim, to keep attestors independent of the nullifier. It costs a second hash and puts `verifyAttestation` back at about 19,000 rows.

All three, like this one, depend on Midnight's Poseidon through the Schnorr challenge.

Consequences:

- The observation identity (its fields, their order, their types and the hash) is now part of what attestors sign. Changing it is a layout change: it changes the message, so it needs an attestor release, and once a layout is deployed it needs a version bump.
- The signed `version` is what separates one nullifier construction from the next: a later construction ships under a new version, so a signature made under the old one cannot be passed off under the new one. Until a layout is deployed, `version` stays `1`.
- A kind builds the message with `claimToMessage` and the nullifier with `nullifierOf` from `@txpipe/thoth-core/claim`; neither needs a key.
- `holder` stays outside the nullifier ([ADR 0006](0006-nullifier-keys-on-the-observation-identity.md)), so it is signed on its own.
