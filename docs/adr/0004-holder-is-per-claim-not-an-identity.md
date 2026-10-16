# Holder is a per-claim binding, not a user identity

Status: accepted. The "no per-attestment salt" below is about the holder commitment's randomness. The claim's nullifier salt ([ADR 0012](0012-nullifier-hashes-a-secret-attestor-derived-salt.md)) is a separate value the kind derives from the evidence, not client randomness.

The attestation layer binds each claim to a per-claim holder commitment. It does not track a user across claims. `holder` is therefore a fresh value per claim by default: attestors cannot link a user across claims, and only the owner of that claim's secret can vault it. Cross-claim or per-user state is the app's job, built on top by reusing a secret deliberately or by keeping its own claim-to-user mapping. This makes privacy the default and state opt-in, and resolves the holder-linkability finding (#23) as a design stance rather than a fix. It also means the library needs no stable secret and no per-attestment salt: a fresh secret is already the randomness.
