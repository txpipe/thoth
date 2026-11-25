---
'@txpipe/thoth-contracts': patch
---

`verifyAttestation` no longer asserts `Claim already accepted`. The assert could never fire: an equal vault id commits to the same claim, and the replay check has already rejected that claim's nullifier with `Observation replay`.
