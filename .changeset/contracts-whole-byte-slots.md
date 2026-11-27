---
'@txpipe/thoth-contracts': minor
---

A byte slot is one `Bytes<32>` with one presence flag. Embed `attestation<V, W, N, M>`, where `W` is the byte-slot count (it was the half count `B = 2W`); `Claim` and `Observation` carry `byteValues: Vector<W, Bytes<32>>` and `bytePresent: Vector<W, Boolean>`. A predicate compares `byteValues[i]` to a `Bytes<32>` directly, so opening a byte value proves at `k = 14` instead of `k = 15`. The message signs `W`, the nullifier hashes each value whole, and an absent byte slot must be all zero (`Absent slot has nonzero value`). A signature made for the old shape no longer verifies.
