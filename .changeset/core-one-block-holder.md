---
'@txpipe/thoth-core': minor
---

`holderCommitmentOf` returns the SHA-256 of the 22-byte tag `thoth:holder-commit:v1`, then the secret, equal to the contract's new `holderCommitment`. A holder commitment made with an earlier release no longer matches the contract.
