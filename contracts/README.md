# Thoth Compact contracts

The Thoth on-chain layer: three embeddable modules plus an example top-level
embedding.

| File | Module | Role |
|------|--------|------|
| `attestation.compact` | `attestation<#K, #V, #N, #M>` | Verifies N-of-M signatures over a flat signed message, controls replay (`nullifiers`) and freshness (`freshnessWindow`), stores a `claimsVault` entry keyed by `persistentCommit(claim, rand)`. The claim can be opened at any time to access the values.|
| `attestor_registry.compact` | `attestor_registry<#M, #K>` | Pinned attestor public keys (sealed) + `countValidSignatures` over a `Vector<K, Field>` message. Counts only — no threshold |
| `schnorr.compact` | `schnorr` | Jubjub Schnorr verification polyfill (generic `Vector<#n, Field>`) |
| `examples/example_app.compact` | top-level | Example app embedding `Attestation<9, 3, 2, 3>` (2-of-3) |

## Module parameters

`attestation<#K, #V, #N, #M>` — embed as `import "attestation"<K, V, N, M>`:

- `#K` — signed-message length in fields (`K` must equal `V + 6`)
- `#V` — number of claim value slots (`Claim.values: Vector<V, Uint<64>>`)
- `#N` — the app's N-of-M threshold
- `#M` — number of attestor signatures supplied / registry key slots

All are fixed when a contract embeds the module.

## The signed message (contract law)

`buildMessage` (`attestation.compact`) flattens a `Claim` into exactly
`Vector<K, Field>` fields, in this order:

```
[ version, kind, timestamp,
  degradeToTransient(nonce), degradeToTransient(evidenceHash), present,
  values[0] as Field, ..., values[N-1] as Field ]
```

The attestor MUST reproduce this exact flat field vector to sign the same
message (same order, sizes, `present` bitmask semantics, and the two
`degradeToTransient` transforms). `present` is a `Uint<N>` bitmask: bit `i` set
means `values[i]` was populated (its value may still be `0`).

## Deploy wiring

Both `freshnessWindow` (Attestation) and `keys` (Registry) are **sealed** ledgers
set exactly once in the top-level constructor. See `examples/example_app.compact`
for the full wiring.

## Opening a vaulted claim

`attestation.openClaim(id): Claim` proves the caller owns a vaulted claim
(claimsVault membership + holder match + `persistentCommit(claim, commitRand)
== id`) and re-hydrates the `Claim` in-circuit. Apps compose predicates over the
returned `Claim` inside their own circuits — one open, read any subset of
`values[i]` (attestors signed the whole claim).

- **Never re-export `openClaim` as a top-level contract entry point.** Its
  return value is witness/ledger tainted; a top-level export would force a
  `disclose()` that publishes every value on-chain. Compose it in-circuit only.
- **Consumes no nullifier** — opening is repeatable. "Use once" rules (e.g. the
  same claim can mint a given badge at most once) are enforced by the **app's
  own state** (`Set`/`Counter`/map), not by claim nullification.
  Nonce replay (depositing the same attested fact twice) is already prevented by `verifyAttestation`.

## Notes / open questions

- Reusability across apps: the claim shape is positional (`values: Vector<N, Uint<64>>`)
  plus a `present` mask. It is simple enough that any app can parse it, but the
  *meaning* of each slot is app-defined. There is no per-value tag in the signed
  message; the provider is identified by `kind`.