---
'@txpipe/thoth-client': minor
---

Add `slotSignaturesOf(collected)`, which names each collected signature by its registry slot, in slot order, as the `{ registryIndex, signature }` entries a contract's `getSignatures` witness returns. It throws a `RangeError` if a slot is not an integer in `[0, 65535]`, the contract's `Uint<16>` range, or two attestations name one slot.
