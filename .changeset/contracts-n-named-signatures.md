---
'@txpipe/thoth-contracts': minor
---

The registry checks exactly `N` signatures, each named by its registry slot, instead of one signature per slot. Implement a new witness, `getSignatures`, that returns `N` entries `{ registryIndex, signature }` in strictly increasing slot order, and return only the claim from `getAttestationWitness`; send no dummy for a slot that did not sign. Each signature is verified with the standard library's `jubjubSchnorrVerify` against its slot's key, and which slots signed stays private. A repeated or out-of-order slot fails with `Registry slots not increasing`, a slot at or past `M` with `Registry slot out of range`, an empty slot with `Empty registry slot`, and a signature that does not verify with `Insufficient valid signatures`. `countValidSignatures` is replaced by `requireSignatures<N>`. `verifyAttestation` falls to 12,177 rows on the numeric mock and 14,123 on the bytes mock.
