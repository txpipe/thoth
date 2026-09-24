# @thoth/core

Core types and definitions for the Thoth N-of-M attestation system.

Thoth lets Midnight contracts accept externally attested information with ZK
privacy. `@thoth/core` is the shared, **keyless** contract law: the claim shape,
the attestor definition schemas, and the client-facing attestor descriptor. It
carries no signing key and no host machinery, those live in
[`@thoth/attestor`](https://github.com/txpipe-shop/thoth/tree/main/packages/attestor).

## Install

```bash
npm install @thoth/core
```

## What's in it

The package exposes two entry points:

- **`@thoth/core`**:
  - `AttestationInput<P, E, C>` — the raw policy / evidence / claim submitted to an attestor
  - `AttestorDefinition<K, P, E, C>` — the shareable, keyless law a kind of attestor implements: zod schemas for `policy`/`evidence`/`claim`, plus `verify` (decide whether to attest) and `message` (encode a claim into the message type)
  - `AttestorDescriptor<D, PK>` — the client-facing face of an attestor: everything a client needs to address it
  - `Attestation<K, C, PK, S>` — the signed artifact an attestor produces and a client collects
- **`@thoth/core/claim`**:
  - `Claim<V>` / `ClaimInput<V>` — the canonical claim: an 8-field header (version, kind, policyDigest, requestBinding, holder, nonce, windowStart, windowEnd), a `present` mask, and `V` numeric `values`
  - `claimSchema<V>(v?)` — a zod schema that validates and coerces a raw claim payload into the canonical claim shape; omit `v` to accept any value count
  - `claimToMessage` — encode a parsed `Claim` into the exact `FlatMessage` the contract's `buildMessage` verifies
  - `FlatMessage` — a Compact `Vector<K, Field>` as a `readonly bigint[]`

### The claim layout

The claim is *common*: it holds only facts every attestor observing the same
intent shares, and nothing specific to one piece of evidence, so independent
observations of the same fact sign the same message. In wire order:

| Field | Size | Meaning |
| --- | --- | --- |
| `version`, `kind` | 1 field each | schema version and kind code (both `1` today) |
| `policyDigest` | 32 bytes | digest of the policy the claim was attested under |
| `requestBinding` | 32 bytes | digest of the certified request identity |
| `holder` | 32 bytes | the holder commitment the claim is bound to |
| `nonce` | 32 bytes | the operation nonce; replay protection |
| `windowStart`, `windowEnd` | Unix seconds | the observation window |
| `present` | `V` flags | `present[i]` means slot `i` was measured, even if its value is `0` |
| `values` | `V` fields | the numeric values |

`claimToMessage` maps each 32-byte field to one field element with
`degradeToTransient`, exactly as the circuit does, so a message is `2*V + 8`
fields long. Encoding vectors in `test/claim-vectors.json` pin known claims to
their field vectors; the contracts parity test checks the encoder and the
circuit against them. The kinds decide what the 32-byte fields hold — the core
stays keyless and knows nothing of policies or requests.

### The flat message type

`FlatMessage` is the **default** signed-message type. It's the default for a
`Msg` generic threaded through `AttestorDefinition`, `AttestorSigner`, `KeyPair`
and `Attestation`, so a standard kind never mentions it. A kind that needs a
different message shape opts in by giving its `message()` another return type
(derived via `MessageOf<D>`), and the whole host stack agrees with the
definition. `claimToMessage` is the canonical encoder for the standard shape —
it mirrors the contract's `buildMessage` byte-for-byte, guarded by the parity
test in the contracts suite.

```ts
import { claimSchema, claimToMessage } from '@thoth/core/claim';
import type { Claim } from '@thoth/core/claim';
import type { AttestorDefinition } from '@thoth/core';

// A kind's definition uses the claim schema as its claim law.
const def: AttestorDefinition<'zkfetch', z.ZodType, z.ZodType, z.ZodType> = {
  kind: 'zkTLS',
  policy: /* … */,
  evidence: /* … */,
  claim: claimSchema<8>(8),
  verify: () => {},
  message: (claim) => claimToMessage(claim),
};
```

## Links

- [Thoth (repo root)](https://github.com/txpipe-shop/thoth) — overall architecture and docs
- [docs/DESIGN.md](https://github.com/txpipe-shop/thoth/blob/main/docs/DESIGN.md) — design overview
- [`@thoth/attestor`](https://github.com/txpipe-shop/thoth/tree/main/packages/attestor) — the host (key boundary, instances)
- [`@thoth/contracts`](https://github.com/txpipe-shop/thoth/tree/main/packages/contracts) — the on-chain Compact modules the claim shape mirrors