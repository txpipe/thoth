# The vault pseudonym survives network upgrades

Status: accepted

The claims vault stores a pseudonym of each holder secret, and `openClaim` recomputes it to check the caller. It must therefore give the same value for as long as a claim stays vaulted. It was `jubjubPointX(hashToCurve(tag, secret))`. Midnight documents `transientHash` as "not guaranteed to persist between upgrades" and says it "should not be used to derive state data"; `hashToCurve` is built on the same Poseidon gadget in `midnight-transient-crypto`, whose `transient_hash` "may be changed on hard-forks", and its stability is not documented. A hard fork that changed it would make every vaulted claim unopenable.

The pseudonym is now `jubjubPointX(ecMulGenerator(s))`, where `s` is the secret's first 31 bytes read little-endian (`degradeToTransient`). It is curve arithmetic on Jubjub with its fixed generator, so it changes only if the embedded curve does, which would also invalidate every registry key.

Considered options:

- `persistentHash` of a tagged secret. SHA-256 is documented as stable, but it costs one 2,000-row block in `verifyAttestation` and in every `openClaim`. That puts the mock's `openAndRead` at 8,270 rows, past the 8,192-row boundary that halves proving time.
- Deriving the pseudonym from the holder commitment. Opening would then cost two hashes, and the commitment must stay off-chain: in zkFetch it is the salt's only secret input.

Consequences:

- The pseudonym costs about 370 rows more than `hashToCurve`, in `verifyAttestation` and in `openClaim`.
- The pseudonym ignores the secret's last byte. A holder secret carries 248 bits of entropy into it, which is more than Jubjub's discrete-log security.
- The pseudonym is the public key of `s`. Use the holder secret only as a holder secret, never as a signing key.
- `openClaim` takes `s` itself as a `JubjubScalar` witness (`getHolderScalar`) instead of the secret. Owning the pseudonym is knowing `s`: `s * G` lies in the prime-order subgroup, where no other point has its x coordinate. It skips a 370-row conversion in every `openClaim`, and it keeps the open circuits provable: with compiler 0.36.1 and proof server 9.0.0, a circuit whose only Jubjub values come from converting a `Field` to a scalar gets a proving key the proof server cannot read (it panics reading the key), and the open circuits have no other Jubjub input once the signatures have their own witness ([ADR 0015](0015-contract-verifies-n-named-signatures.md)). `verifyAttestation` still derives `s` from the secret, which ties it to the holder commitment.
