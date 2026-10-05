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

- `TrustedSet<D, PK>` — the client's pinned attestors plus the on-chain
  registry's size (`registrySize`, the contract's `#M`). It is **unordered**:
  the array carries no order. Each member is a `TrustedAttestor` — an
  [`AttestorDescriptor`](https://github.com/txpipe-shop/thoth/tree/main/packages/core)
  (`id`, keyless `definition`, `publicKey`) paired with the `registryIndex`
  **this app** assigned it. The slot is the app's placement, not a property of
  the attestor.
- `buildTrustedSet({ registrySize, attestors })` — assemble the checked trusted
  set: rejects an invalid registry size, an empty set, duplicate ids, duplicate
  public keys, duplicate slots, and slots outside `[0, registrySize)`
  (`InvalidTrustedSetError`, from `@thoth/client/errors`).
- `memberOf(trusted, id)` — resolve a string-named attestor to its trusted
  member (descriptor + slot). `attestorOf(trusted, id)` returns the descriptor
  alone, and `attestorIdsOf(trusted)` lists every member's id.
- `AttestorTransport<D, PK, S>` — the seam between the client and a remote
  attestor: `request(attestor, input): Promise<Attestation>`. A kind SDK or the
  app supplies the concrete transport. The host-side mirror is `Attestor.attest` in `@thoth/attestor`.
- `await resolveAttestation({ trusted, member, attestation, verifier, expectedClaim, expectedMessage? })` —
  checks trusted-set membership (by id, slot, and key, so a copied member is
  accepted), the pinned key, expected claim, signature, claim-to-message
  binding, and optionally the expected message, then tags the
  attestation with the member's slot as a `CollectedAttestation`.
- `CollectedAttestation<C, PK, S, Msg>` — the collection output shape:
  an `Attestation` plus the `registryIndex` it belongs to.
- Errors: `AttestationMismatchError` (thrown by `resolveAttestation`; `reason`
  is `'public-key' | 'message' | 'claim' | 'signature'`),
  `AttestorNotInTrustedSetError`, `InvalidTrustedSetError` (thrown by
  `buildTrustedSet`) — exported from `@thoth/client/errors`.

## For kind SDK authors

Kind-specific SDKs (e.g. [`@thoth/zk-tls`](https://github.com/txpipe-shop/thoth/tree/main/packages/zk-tls)) build *on top of* this package: they
wire a concrete transport, drive the fan-out in their own async runtime, apply
their own threshold policy, and add their own prove/attest ergonomics.

### Assemble the trusted set

`buildTrustedSet({ registrySize, attestors })` is the one construction helper
every kind SDK shares. The app supplies each attestor's slot from its own
deployed registry, and the registry's key count bounds those slots. A set may
pin fewer attestors than the registry holds. It rejects an invalid registry
size, an empty set, duplicate ids, duplicate public keys, duplicate slots, and
out-of-range slots, so a `TrustedSet` is valid by construction (or not built at
all).

```ts
import { buildTrustedSet } from '@thoth/client';

// throws InvalidTrustedSetError if malformed
const trusted = buildTrustedSet({
  registrySize: 3, // the contract's #M
  attestors: [
    { attestor: txpipeDescriptor, registryIndex: 0 },
    { attestor: eryxDescriptor, registryIndex: 2 },
  ],
});
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
  ): Promise<Attestation<MyClaim, MyPublicKey, MySignature, MyMessage>> {
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

`memberOf(trusted, id)` is the name→member lookup behind a friendly
`proof.attest("txpipeEndpoint", …)` API, without each SDK re-checking
membership:

```ts
// throws AttestorNotInTrustedSetError if not pinned
const member = memberOf(trusted, 'txpipeEndpoint');
await transport.request(member.attestor, input); // transports never see the slot
```

### Vet one attestation

Supply an `AttestationVerifier<PK, S, Msg>` whose `verify(publicKey, message,
signature)` returns a boolean or a promise. `resolveAttestation` requires that
verifier and the parsed `expectedClaim`. It rejects a different claim,
a message that does not encode the returned claim, and an invalid signature.
Verifier errors become a `'signature'` mismatch; a returned claim that differs
from the expected claim becomes a `'claim'` mismatch. The caller must parse the
expected claim first. Vetting compares schema outputs without applying input
transforms again. The result is a promise of a slot-tagged attestation.

For the contract's Jubjub Schnorr scheme, use the adapter from the separate
`@thoth/client/jubjub` entry point. It uses Compact runtime `0.19.0`, the same
version as the contracts. The generic entry point imports no crypto library.

```ts
import { resolveAttestation } from '@thoth/client';
import { jubjubVerifier } from '@thoth/client/jubjub';

const collected = await resolveAttestation({
  trusted, member, attestation,
  expectedClaim: claim,
  verifier: jubjubVerifier,
});
// Place collected.attestation.signature at collected.registryIndex.
```

### Design rationale

The client verifies attestor signatures before collecting them. A broken or
malicious transport can otherwise return a forged signature with the correct
public key and message, causing a transaction to fail after submission and
costing fees. The returned claim must match the expected claim and encode the
signed message. Kind identity belongs to the pinned definition, so the response
carries no kind label to check. For zkFetch, the signed policy hash commits to
the law tag, policy, and wire version. Contract verification still enforces the
registry and N-of-M threshold. Transport implementations must decode wire
values into the typed attestation before vetting.

Registry slots belong to the trusted set, not to attestors. The signed message
binds no slot, registry, or contract, so one attestor can serve many apps at
different slots. Each app records the slot its own registry assigned, and
`registrySize` (the registry's `#M`) bounds it. A set may pin fewer attestors
than the registry holds. `resolveAttestation` takes the trusted member itself,
so a result can only carry a slot the set assigned. Transports receive only the
descriptor.

## Links

- [Thoth (repo root)](https://github.com/txpipe-shop/thoth) — overall architecture and docs
- [docs/DESIGN.md](https://github.com/txpipe-shop/thoth/blob/main/docs/DESIGN.md) — architecture overview and flow
- [`@thoth/core`](https://github.com/txpipe-shop/thoth/tree/main/packages/core) — `AttestorDescriptor`, `Attestation`, `AttestationInput`
- [`@thoth/attestor`](https://github.com/txpipe-shop/thoth/tree/main/packages/attestor) — the host-side `Attestor`/`Attest` these types mirror
- [`@thoth/contracts`](https://github.com/txpipe-shop/thoth/tree/main/packages/contracts) — the on-chain registry that verifies the signatures positionally
