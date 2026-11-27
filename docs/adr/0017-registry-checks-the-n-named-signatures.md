# The registry checks the N signatures the prover names

Status: accepted

The registry verified one signature per registry slot: `signatures[i]` against `keys[i]`, for all M slots, and counted the ones that verified against the threshold N. A dApp filled every slot that did not sign with a dummy signature, and each of the M slots cost a full Schnorr verification, about 1,500 rows. A registry that grew made every proof slower, though only N signatures ever counted. Issue #309 measured this as the last avoidable cost in `verifyAttestation`.

The registry now checks exactly N signatures, each against the slot it names. The `getSignatures` witness returns N entries of a registry slot and a signature (`SlotSignature`), and `requireSignatures` requires that:

- the slots strictly increase, so no slot counts twice;
- the last slot is below M, which bounds all of them;
- each slot holds a key, since an empty slot has no attestor behind it;
- each signature verifies over the message against its slot's key, with the standard library's `jubjubSchnorrVerify`.

A slot is a `Uint<16>`, so M is at most 65,536. Because `initRegistry` rejects a key pinned in two slots, N distinct slots are N distinct attestors.

The slots are private inputs. A vector subscript must be a constant, so the circuit selects a slot's key by comparing the slot with every one of the M slots, and reads the whole key vector whichever slots are named. No ledger operation and no disclosed value depends on a slot: two submissions of one claim from different slots leave the same public transcript.

The signatures have a witness of their own. `getAttestationWitness` returns only the claim, so `openClaim`, which reads the same witness, no longer takes signature inputs it never checks.

Considered options:

- Keep verifying every slot. It costs M signature verifications whatever N is, and a dApp has to send a dummy for each slot that did not sign.
- Require the slots to be pairwise distinct instead of increasing. It costs N² comparisons against N, and an increasing order also gives the client one canonical order to hand over.
- Disclose the slots, or a bitmap of them. It would let the circuit read one key instead of M, and would reveal which attestors signed every claim.
- Replace the standard library's verifier with a hand-written Schnorr equation over a scalar-typed response. It saves about 350 rows per signature and needs an independent cryptographic review; it is out of scope here.

Consequences:

- `verifyAttestation` falls from 13,646 to 12,177 rows on the numeric mock and from 15,593 to 14,123 on the bytes mock (2-of-3, `k = 14`). The open circuits each lose the 18 rows their unused signature inputs cost.
- A claim's proof grows with N. It grows with M only through the key selection, a comparison and a select per slot for each signature.
- One invalid signature fails the proof instead of not being counted. The dApp sends exactly N signatures that its client already verified; `slotSignaturesOf` in `@txpipe/thoth-client` turns a kind's collected attestations into the witness value, in slot order.
- The registry slot travels in the witness next to its signature instead of being implied by its position. It still comes only from the app's trusted set, never from the order replies arrive in.
