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
  - `Claim<V>` / `ClaimInput<V>` — the canonical claim: 5-field header (version, kind, timestamp, nonce, evidenceHash), a `present` mask, and `V` numeric `values`
  - `claimSchema<V>` — a zod schema that validates and coerces a raw claim payload into the canonical claim shape
  - `claimToMessage` — encode a parsed `Claim` into the exact `FlatMessage` the contract's `buildMessage` verifies
  - `FlatMessage` — a Compact `Vector<K, Field>` as a `readonly bigint[]`

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
- [docs/DESIGN.md](https://github.com/txpipe-shop/thoth/blob/main/docs/DESIGN.md) — design overview and decisions
- [`@thoth/attestor`](https://github.com/txpipe-shop/thoth/tree/main/packages/attestor) — the host (key boundary, instances)
- [`@thoth/contracts`](https://github.com/txpipe-shop/thoth/tree/main/packages/contracts) — the on-chain Compact modules the claim shape mirrors