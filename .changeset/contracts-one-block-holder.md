---
'@txpipe/thoth-contracts': minor
---

`holderCommitment(secret)` is the SHA-256 of the 22-byte tag `thoth:holder-commit:v1`, then the secret: one SHA-256 block instead of two, about 1,850 fewer rows in `verifyAttestation`. A claim whose holder was committed with an earlier release fails with `Holder mismatch`; recompute it with `holderCommitmentOf` from the matching `@txpipe/thoth-core` release.
