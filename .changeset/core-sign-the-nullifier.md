---
'@txpipe/thoth-core': minor
---

`claimToMessage` returns the seven fields the contract's `buildMessage` rebuilds: the claim's version, its layout, its nullifier and its holder. The new `nullifierOf` returns the claim's nullifier, the SHA-256 of its observation identity, equal to the contract's. A signature made over the old message no longer verifies.
