# The contract verifies N named signatures

Status: accepted

The registry verified all M signatures and counted those that held, so a 2-of-3 contract paid three Schnorr verifications and a 5-of-8 contract eight, and the witness carried a dummy signature in every slot that did not sign. A verification was about 1,620 rows at K = 20, so signatures were a large share of `verifyAttestation` once the byte splitting is gone (issue #192 measures the cost).

The witness now names the N registry slots it uses. `getSignatures` returns N entries `{ registryIndex, signature }`, and `requireSignatures` checks each signature only against `keys[registryIndex]`, selected by comparing the index with every slot, since a vector subscript must be a constant. The slots must be strictly increasing, so no slot counts twice, and must hold a key: the empty key would accept a forged signature, and an index at or past M selects the empty key. A slot is a `Uint<8>`.

The registry verifies with its own copy of the stdlib check, `s·G == R + c·pk` with `c = transientHash(R.x, R.y, pk.x, pk.y, msg)`, over a signature whose response is a `JubjubScalar`. The values are those of the runtime's `JubjubSchnorrSignature`, so attestors keep signing with `jubjubSchnorrSign`. The stdlib takes the response as a `Field` and converts it to a scalar in-circuit, which costs about 390 rows; a scalar witness costs about 60. The signatures have a witness of their own, so the `openClaim` circuits do not pay for scalar inputs they never read.

Considered options:

- Keep verifying M with the scalar response alone: saves about 350 rows per slot, but the cost still grows with M.
- Hash the message once in the registry and verify every signature over the one-field digest: saves about 11 rows per message field per signature, minus one hash of the message, so about 180 rows at 2-of-3 and K = 20. It changes what attestors sign, so it belongs to the wire format, not the registry. [ADR 0014](0014-attestors-sign-the-nullifier.md) makes the message seven fields, the version, the layout, the nullifier and the holder, so there is no long message left to hash. The registry takes the message's type as a module parameter, and its challenge absorbs a struct message as `transientHash` flattens it, so the two 32-byte values enter without slicing.
- Aggregate the N signatures into one (a multisignature over the sum of the N keys): one verification for any N, about 4,700 rows less at 5-of-8, but signing becomes an interactive protocol between attestors, and a plain key sum needs proof of possession at registration against rogue keys.
- Batch verification with random weights: needs a scalar multiplication per announcement, so it costs as much as verifying each signature.
- Pairwise-distinct slots in any order: as cheap, but the order is not canonical; increasing order is the slot order the client already uses.

Consequences:

- The witness changes: `getSignatures` returns exactly N slot signatures in increasing slot order, and `getAttestationWitness` no longer carries signatures. A dApp with fewer than N signatures cannot submit; there are no dummies.
- Proving cost grows with N, not M: about 1,250 rows per signature plus 11 per message field (seven fields with ADR 0014), plus about 4 rows per signature per registry slot for the selection. At 2-of-3, K = 20, `verifyAttestation` drops by 2,319 rows; at 5-of-8 by about 6,500.
- Which slots signed stays private: the indices are witness data and the circuit reads every key, so the public transcript is the same for every subset.
- The registry's verifier must match the runtime's `jubjubSchnorrSign`. Both are pinned with compact-runtime `0.21.0`; a runtime upgrade that changes the challenge breaks acceptance, which the simulator tests catch.
- A registry of more than 256 keys cannot name the slots past 255.
