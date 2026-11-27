# The claims vault is keyed by the nullifier

Status: accepted

The claims vault used to be keyed by a claim id, `persistentCommit(claim, rand)`, with 32 bytes of commitment randomness the holder chose and kept, and replay was a separate nullifier set. `verifyAttestation` hashed nearly the same fields twice, once for the nullifier and once for the id, and every `openClaim` recomputed the id. Issue #309 measured the second hash at about a third of what was left of `verifyAttestation` once attestors signed the nullifier ([ADR 0015](0015-attestors-sign-the-nullifier.md)).

The vault is now keyed by the nullifier. `verifyAttestation` rejects a nullifier already in the vault (`"Observation replay"`) and inserts the entry under it, so vault membership is the replay check. There is no nullifier set, no claim id and no commitment randomness in the witness or the holder's private state. A holder opens a claim with its nullifier, which `nullifierOf(claim)` in `@txpipe/thoth-core/claim` computes from the claim the holder already has, and their secret. The vault entry (vault pseudonym and window) and the vault pseudonym's derivation do not change.

`openClaim(nullifier)` returns the observation identity, the fields the nullifier binds, and not `holder` or `version`. It checks that the entry exists, that the caller's pseudonym owns it, and that the witness's claim hashes to the nullifier. The nullifier does not cover `holder` or `version`, so the witness could carry any value for them. Returning them would hand a predicate two fields the circuit never checked; their absence from the returned type makes a predicate that reads either one fail to compile.

**The vault key hides no more and no less than the nullifier.** The nullifier is public: `verifyAttestation` discloses it for the replay check, in the same transaction that writes the vault entry. The claim id hid the claim from anyone without `rand`, but the transaction that inserted it also inserted the claim's nullifier, so anyone reading the ledger could already link each vault entry to its nullifier. Keying the vault by the nullifier publishes nothing that transaction did not already publish, and the ledger keeps one 32-byte value per claim instead of two.

- In zkFetch the nullifier hashes a secret salt ([ADR 0012](0012-nullifier-hashes-a-secret-attestor-derived-salt.md)), so the vault key cannot confirm a guessed value either.
- A chain-event kind's salt is public ([ADR 0014](0014-chain-event-kinds.md)), so anyone can recompute its nullifier from the event, and the vault key reveals which event a claim attests. The nullifier in the same transaction already revealed that, and the vault entry was already linked to it through that transaction. What the entry adds about the event is its vault pseudonym and window, which it disclosed under the claim id too; the window is the event's block time, public on the source chain. An app that cannot bear the event linkage needs the salted variant ADR 0014 leaves undesigned, for the vault key and the nullifier alike.

Considered options:

- Keep the claim id. It costs a second SHA-256 in `verifyAttestation` and in every `openClaim`, and the holder must keep randomness per claim, without hiding anything the nullifier does not already reveal.
- Key the vault by another hash of the nullifier, or of the nullifier and a holder value. Any function of the nullifier alone is as linkable as the nullifier, and adding a holder value brings back randomness to keep.
- Return the whole claim from `openClaim` and check `holder` against the caller's secret and `version` against `1`. It costs a holder commitment hash per open, and a predicate needs neither field: holder state belongs on the vault pseudonym, and the version was checked when the claim was accepted.

Consequences:

- `verifyAttestation` falls from 21,253 to 13,646 rows on the numeric mock and from 25,076 to 15,599 on the bytes mock (`k = 14`). `openAndRead`, `openAndReadPresence` and `openAndRequireMetric0` fall from about 8,600 rows to about 6,650 (`k = 13`).
- A vault entry is the record that an observation was accepted. Removing one would let the same observation be accepted again; only `verifyAttestation` writes the vault, and issue #304 tracks enforcing that.
- A kind's `getAttestationWitness` returns the claim and the signatures, nothing else. The client holds no vault state beyond the holder secret.
- A predicate reads the observation identity's fields from `openClaim`. One that needs the claim's holder keys its state on the vault pseudonym (`holderOf(secret)`) instead.
