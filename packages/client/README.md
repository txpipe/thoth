# @thoth/client

Client-side base for the Thoth N-of-M attestation system.

Thoth lets Midnight contracts accept externally attested information with ZK
privacy. `@thoth/client` is the **dApp-side generic base**: the types and the
per-attestation validity primitive a client uses to address the attestors in
its trusted set and assemble the N-of-M signature set.

## Install

```bash
npm install @thoth/client
```

## What's in it

- `TrustedSet<D, PK>` — the client's pinned attestors. It is **unordered**: the
  array carries no order — each member's `registryIndex` is its on-chain
  registry slot, never its position in the list. Each member is an
  [`AttestorDescriptor`](https://github.com/txpipe-shop/thoth/tree/main/packages/core):
  `id`, its keyless `definition`, its `publicKey`, and its `registryIndex`.
- `buildTrustedSet(attestors)` — assemble the checked trusted set: rejects an
  empty set, duplicate ids, duplicate or out-of-range `registryIndex` slots
  (`InvalidTrustedSetError`, from `@thoth/client/errors`).
- `attestorOf(trusted, id)` — resolve a string-named attestor to its descriptor.
- `AttestorTransport<D, PK, S>` — the seam between the client and a remote
  attestor: `request(attestor, input): Promise<Attestation>`. A kind SDK or the
  app supplies the concrete transport. The host-side mirror is `Attestor.attest` in `@thoth/attestor`.
- `await resolveAttestation({ trusted, attestor, attestation, verifier, expectedClaim, expectedMessage? })` —
  checks the pinned key, kind, expected claim, signature, claim-to-message
  binding, slot bounds, and optionally the expected message, then tags the
  attestation with its slot as a `CollectedAttestation`.
- `CollectedAttestation<K, C, PK, S, Msg>` — the collection output shape:
  an `Attestation` plus the `registryIndex` it belongs to.
- Errors: `AttestationMismatchError` (thrown by `resolveAttestation`; `reason`
  is `'public-key' | 'message' | 'registry-index' | 'kind' | 'claim' | 'signature'`),
  `AttestorNotInTrustedSetError`, `InvalidTrustedSetError` (thrown by
  `buildTrustedSet`) — exported from `@thoth/client/errors`.

## For kind SDK authors

Kind-specific SDKs (e.g. [`@thoth/zk-tls`](https://github.com/txpipe-shop/thoth/tree/main/packages/zk-tls)) build *on top of* this package: they
wire a concrete transport, drive the fan-out in their own async runtime, apply
their own threshold policy, and add their own prove/attest ergonomics.

### Assemble the trusted set

`buildTrustedSet(attestors)` is the one construction helper every kind SDK
shares: it rejects an empty set, duplicate ids, duplicate `registryIndex`
slots, and out-of-range slots, so a `TrustedSet` is valid by construction (or
not built at all).

```ts
import { buildTrustedSet } from '@thoth/client';

const trusted = buildTrustedSet(descriptors); // throws InvalidTrustedSetError if malformed
```

### Implement the transport

The single interface a kind SDK must supply is `AttestorTransport`. Both sides
of it speak `@thoth/core` types, so it mirrors the host-side `Attestor.attest`
exactly: a descriptor and the raw input in, an `Attestation` out (or throw).
A minimal HTTP implementation:

```ts
import type { Attestation, AttestationInput } from '@thoth/core';
import type { AttestorDescriptor, AttestorTransport } from '@thoth/client';

const httpTransport: AttestorTransport<MyDefinition, MyPublicKey, MySignature> = {
  async request(
    attestor: AttestorDescriptor<MyDefinition, MyPublicKey>,
    input: AttestationInput<MyPolicy, MyEvidence, MyClaim>,
  ): Promise<Attestation<MyDefinition['kind'], MyClaim, MyPublicKey, MySignature, MyMessage>> {
    const res = await fetch(`${attestor.id}/attest`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(input),
    });
    if (!res.ok) throw new Error(`attestor ${attestor.id} rejected: ${res.status}`);
    return res.json();
  },
};
```

### Resolve string-named endpoints

`attestorOf(trusted, id)` is the name→descriptor lookup behind a friendly
`proof.attest("txpipeEndpoint", …)` API, without each SDK re-checking
membership:

```ts
const attestor = attestorOf(trusted, 'txpipeEndpoint'); // throws AttestorNotInTrustedSetError if not pinned
```

### Vet one attestation

Supply an `AttestationVerifier<PK, S, Msg>` whose `verify(publicKey, message,
signature)` returns a boolean or a promise. `resolveAttestation` requires that
verifier and the parsed `expectedClaim`. It rejects a different kind or claim,
a message that does not encode the returned claim, and an invalid signature.
Verifier errors become a `'signature'` mismatch; invalid returned claims become
a `'claim'` mismatch. The result is a promise of a slot-tagged attestation.

For the contract's Jubjub Schnorr scheme, use the adapter from the separate
`@thoth/client/jubjub` entry point. It uses Compact runtime `0.19.0`, the same
version as the contracts. The generic entry point imports no crypto library.

```ts
import { resolveAttestation } from '@thoth/client';
import { jubjubVerifier } from '@thoth/client/jubjub';

const collected = await resolveAttestation({
  trusted, attestor, attestation,
  expectedClaim: claim,
  verifier: jubjubVerifier,
});
// Place collected.attestation.signature at collected.registryIndex.
```

### Design rationale

The client verifies attestor signatures before collecting them. A broken or
malicious transport can otherwise return a forged signature with the correct
public key and message, causing a transaction to fail after submission and
costing fees. Kind and claim checks also reject misleading off-chain metadata
that the signed message alone does not authenticate. Contract verification
still enforces the registry and N-of-M threshold. Transport implementations
must decode wire values into the typed attestation before vetting.

## Links

- [Thoth (repo root)](https://github.com/txpipe-shop/thoth) — overall architecture and docs
- [docs/DESIGN.md](https://github.com/txpipe-shop/thoth/blob/main/docs/DESIGN.md) — the registry-slot positional design
- [`@thoth/core`](https://github.com/txpipe-shop/thoth/tree/main/packages/core) — `AttestorDescriptor`, `Attestation`, `AttestationInput`
- [`@thoth/attestor`](https://github.com/txpipe-shop/thoth/tree/main/packages/attestor) — the host-side `Attestor`/`Attest` these types mirror
- [`@thoth/contracts`](https://github.com/txpipe-shop/thoth/tree/main/packages/contracts) — the on-chain registry that verifies the signatures positionally