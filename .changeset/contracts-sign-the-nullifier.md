---
'@txpipe/thoth-contracts': minor
---

Attestors sign seven fields: the claim's version, the layout (`V` and `B`), the nullifier and the holder. `buildMessage` returns a `Vector<7, Field>`, and the message length is no longer a module parameter: embed `attestation<V, B, N, M>` and `attestor_registry<M>`. `verifyAttestation` proves at `k = 15` instead of `k = 17`, with a 49 MB proving key instead of 197 MB. A signature made for the old message no longer verifies.
