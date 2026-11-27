---
'@txpipe/thoth-contracts': minor
---

The claims vault is keyed by the claim's nullifier. `verifyAttestation` rejects a nullifier already in the vault with `Observation replay` and vaults the claim under it; the `nullifiers` ledger, the `computeId` circuit and the commitment randomness are gone, so `getAttestationWitness` returns `[claim, signatures]`. `openClaim(nullifier)` takes the nullifier (`nullifierOf(claim)` from `@txpipe/thoth-core/claim`) and returns the claim's `Observation`, without `holder` or `version`; a claim that does not hash to it fails with `Claim does not match nullifier`. `verifyAttestation` proves at `k = 14` on both mocks and opening a numeric claim at `k = 13`.
