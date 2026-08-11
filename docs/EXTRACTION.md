# Extraction map — Witness Fitness → Thoth

What proven functionality ports from the Witness Fitness repo into Thoth when code
starts, and which design-doc milestone (see `ATTESTOR-NETWORK-DESIGN.md` §9) needs it.
Source locations are directory-level; the exact files are chosen when each port lands.

| Functionality | What it proves | Source (witness-fitness) | Port target |
|---|---|---|---|
| Jubjub-Schnorr signature verification | The polyfill, verified against the pinned compiler; stdlib `jubjubSchnorrVerify` confirmed absent (compile probe) | `packages/contract` | design §4.4 (M1/M2) |
| Claim encoding + challenge parity | Frozen encoding / `pureCircuits` signing parity mechanism | `packages/contract` | §4.2 (M1) |
| Verification patterns | Threshold counting, distinctness, membership binding, registry semantics | `packages/contract` | §4.2/§4.1 (M1/M3) |
| Credential vault + holder binding + nullifiers | The optional vault companion | `packages/contract` | §4.5 (M3) |
| Attestor-runner pipeline | Reclaim proof re-verification and parity signing | `packages/notary` | §5 (M4) |
| Client flow | zkFetch attestation with fixture fallback | `packages/client` | §5 (M4) |
| Devnet + attestor stacks | Docker compositions for node/indexer/proof-server and the attestor | `devnet/`, `attestor/` | infrastructure (M4/M5) |
| Pinned dependency versions | Compact devtools/compiler/runtime, midnight-js, onchain-runtime, indexer, proof-server, node, pnpm | `package.json`, `pnpm-lock.yaml`; `txpipe-shop/midnight-reference-app/VERSIONS.md` | M4 |
| Reclaim packages | Attestor core + zk-fetch versions | `@reclaimprotocol/attestor-core`, `@reclaimprotocol/zk-fetch` | M4 |

## Do NOT port

Demo-only artifacts stay in Witness Fitness: fixture proofs, demo freshness windows,
rehearsal scripts, and secrets (`.env` files).
