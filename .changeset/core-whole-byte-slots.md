---
'@txpipe/thoth-core': minor
---

`ContractClaim` carries `byteValues` (one 32-byte value per byte slot) and one `bytePresent` flag per slot, matching the contract's new `Claim`; `toContractClaim` no longer splits a value into halves. `claimToMessage` signs the byte-slot count `W`, and `nullifierOf` hashes each byte value whole, so both change for any claim with a byte slot.
