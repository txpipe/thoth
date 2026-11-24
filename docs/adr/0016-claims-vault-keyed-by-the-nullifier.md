# The claims vault is keyed by the nullifier

Status: accepted

`verifyAttestation` hashed every claim three times with SHA-256, at about 2,000 circuit rows per 64-byte block: the holder commitment (2 blocks), the nullifier (3 blocks with `V = 3`, `W = 0`) and the vault key `persistentCommit(claim, rand)` (4 blocks). `openClaim` recomputed the vault key. The vault key and the nullifier are published in the same transaction, so anyone who can recompute the nullifier, such as an attestor that signed the claim, already links it to the vault entry. The commitment's randomness hid nothing the nullifier does not already reveal.

The vault is now keyed by the nullifier. `verifyAttestation` rejects a nullifier that is already a vault key (`"Observation replay"`) and stores the entry under it, and the separate nullifier set is gone. `openClaim(nullifier)` recomputes the nullifier from the caller's claim and returns the `Observation`, the fields the nullifier hashes. It does not return `holder` or `version`, because the nullifier does not bind them: the caller's tie to the claim is the vault pseudonym, and `verifyAttestation` accepts only version `1`.

Considered options:

- A smaller claim commitment, such as `persistentCommit` over the nullifier and the holder. It saves two blocks in `verifyAttestation` but adds one to every `openClaim`, because opening must then recompute both hashes.
- Dropping `appId` from the nullifier. The contract seals one app id, so it adds nothing to uniqueness, and without it the bytes mock's nullifier shrinks from 4 blocks to 3. It stays: for a kind whose salt does not follow the holder, the same observation vaulted in two apps under two holders would then produce the same public nullifier in both contracts and link the two holders.

Consequences:

- `verifyAttestation` drops one hash of the whole claim: about 7,600 rows with `V = 3`, `W = 0`, and 9,500 with one byte value. `openClaim` hashes the observation identity, one block less than the claim commitment.
- The ledger has one fewer field: `nullifiers` is gone, and `claimsVault`'s keys are the nullifiers.
- `getAttestationWitness` returns the claim alone, with no commitment randomness (the signatures have their own witness, [ADR 0015](0015-contract-verifies-n-named-signatures.md)). A dApp opens a claim with `nullifierOf(claim)`.
- An app predicate reads `holder` and `version` from no opened claim. Holder state keys on the vault pseudonym, as before.
- The nullifier is also what the attestors sign ([ADR 0014](0014-attestors-sign-the-nullifier.md)), so `verifyAttestation` hashes the claim once, for the signatures, replay and the vault key.
- The nullifier hides the claim's values only while the salt is secret ([ADR 0012](0012-nullifier-hashes-a-secret-attestor-derived-salt.md)). The vault key now has the same property; the old key and the nullifier were public together, so this hides nothing less.

Amends [ADR 0006](0006-nullifier-keys-on-the-observation-identity.md): the nullifier also keys the claims vault.
