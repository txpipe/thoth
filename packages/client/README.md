# @thoth/client

The dApp side of Thoth, for kind authors writing a kind's client and for apps that use one: the attestors an app pins, the interface to reach them, and the check every returned attestation passes before it is collected.

> **In development.** Thoth is unaudited and has [known security issues](https://github.com/txpipe-shop/thoth/issues?q=is%3Aissue+is%3Aopen+label%3Asecurity). Don't use it to protect real value. The claim format may still change.

## Install

The package is not on npm. Build it from a checkout of this repo and install it by path:

```bash
git clone https://github.com/txpipe-shop/thoth && cd thoth
npm install && npm run build
cd /path/to/your-app && npm install /path/to/thoth/packages/client
```

Its package name is `@thoth/client`; that name may change until the npm scope is settled.

## Usage

A kind's client does three things with this package: build the trusted set from the app's registry, reach one attestor through a transport it supplies, and vet the attestation that comes back.

```ts
import type { JubjubPoint, JubjubSchnorrSignature } from '@midnight-ntwrk/compact-runtime';
import { type AttestorTransport, buildTrustedSet, memberOf, resolveAttestation } from '@thoth/client';
import { jubjubVerifier } from '@thoth/client/jubjub';

// The app assigns each attestor the index of its key in the deployed registry.
const trusted = buildTrustedSet({
  registrySize: 3, // the contract's #M
  attestors: [
    { attestor: alice, registryIndex: 0 },
    { attestor: bob, registryIndex: 2 },
  ],
}); // throws InvalidTrustedSetError

// JSON carries neither bigint nor bytes, so tag them; the attestor's server must use the same pair.
const toJson = (value: unknown): string =>
  JSON.stringify(value, (_, v) =>
    typeof v === 'bigint' ? { $bigint: v.toString() } : v instanceof Uint8Array ? { $bytes: [...v] } : v,
  );
const fromJson = (text: string) =>
  JSON.parse(text, (_, v) =>
    v?.$bigint !== undefined ? BigInt(v.$bigint) : v?.$bytes !== undefined ? Uint8Array.from(v.$bytes) : v,
  );

// Your kind's client supplies the transport; this package only defines the interface.
const transport: AttestorTransport<MyDefinition, JubjubPoint, JubjubSchnorrSignature> = {
  async request(attestor, input) {
    const res = await fetch(`${attestor.id}/attest`, { method: 'POST', body: toJson(input) });
    if (!res.ok) throw new Error(`attestor ${attestor.id} rejected: ${res.status}`);
    return fromJson(await res.text());
  },
};

// Ask one attestor, then vet its answer before collecting it.
const member = memberOf(trusted, 'alice'); // throws AttestorNotInTrustedSetError
const attestation = await transport.request(member.attestor, input);
const collected = await resolveAttestation({
  trusted,
  member,
  attestation,
  expectedClaim: claim, // the parsed claim you asked for
  verifier: jubjubVerifier,
}); // throws AttestationMismatchError
// Place collected.attestation.signature at collected.registryIndex.
```

`attestorOf(trusted, id)` returns the descriptor alone and `attestorIdsOf(trusted)` lists every member's id. The errors come from `@thoth/client/errors`; each carries the attestor's id, and `AttestationMismatchError` and `InvalidTrustedSetError` add a `reason` naming the failed check.

## Concepts

- [Attestor](https://github.com/txpipe-shop/thoth/blob/main/CONTEXT.md#roles): an entity that verifies evidence under a policy and signs a claim. Its descriptor (`id`, keyless `definition`, `publicKey`) comes from [`@thoth/core`](https://github.com/txpipe-shop/thoth/tree/main/packages/core).
- [Trusted set](https://github.com/txpipe-shop/thoth/blob/main/CONTEXT.md#signing-and-collection): the app's pinned attestors, each with its registry slot. `TrustedSet` in code; each member is a `TrustedAttestor`.
- [Registry slot](https://github.com/txpipe-shop/thoth/blob/main/CONTEXT.md#signing-and-collection): the position of an attestor's key in the app's [registry](https://github.com/txpipe-shop/thoth/blob/main/CONTEXT.md#on-chain). `registryIndex` in code, bounded by `registrySize`, the contract's `#M`.
- [Attestation](https://github.com/txpipe-shop/thoth/blob/main/CONTEXT.md#signing-and-collection): the signed artifact one attestor returns, with the claim, the message, its public key and its signature. `CollectedAttestation` pairs one with the slot it answered from.

## Guarantees and limits

- `buildTrustedSet` rejects an invalid registry size, an empty set, duplicate ids, duplicate public keys, duplicate slots and slots outside `[0, registrySize)`, so a `TrustedSet` is valid by construction. It may pin fewer attestors than the registry holds.
- `resolveAttestation` checks that the member is in the trusted set, that the returned key is the pinned key, that the claim equals the parsed claim you asked for, that the message encodes that claim, and that the signature verifies. A verifier that throws counts as an invalid signature. It compares schema outputs and does not apply input transforms again.
- `registryIndex` is positional and app-owned. The contract verifies `signatures[i]` against `keys[i]`, and the signed message binds no slot, registry or contract. You assign each attestor the index of its key in your deployed registry; a wrong slot is not detected here, only by the contract. Never order signatures by anything else.
- The threshold and the registry are enforced by the contract, not here. This package vets one attestation at a time; the kind's client drives the fan-out and the threshold.
- No transport is included. The kind's client or the app supplies one and decodes wire values into the typed `Attestation` before vetting.
- Honest attestors are assumed. Vetting proves who signed, not that what they signed is true; N colluding attestors can certify a false claim (ADR 0003).

## Design decisions

- **Registry slots belong to the trusted set, not to the attestor.** One attestor serves many apps at different slots, so each app records the slot its own registry assigned. `resolveAttestation` takes the trusted member itself, so a result only carries a slot the set assigned, and transports see only the descriptor.
- **Signatures are verified before collection.** A broken or malicious transport could otherwise return a forged signature with the right key and message, and the transaction would fail after submission and cost fees.
- **The verifier is pluggable, and the main entry point imports no crypto library.** `@thoth/client/jubjub` ships the contracts' Jubjub Schnorr scheme on Compact runtime `0.21.0`, the version the contracts pin.
- **The response carries no kind label.** The pinned definition is the kind; for zkFetch the signed policy hash commits to the law tag, policy and wire version ([ADR 0002](https://github.com/txpipe-shop/thoth/blob/main/docs/adr/0002-no-kind-on-chain-policy-hash.md)).

## Links

- [Thoth (repo root)](https://github.com/txpipe-shop/thoth): overall architecture and docs
- [docs/DESIGN.md](https://github.com/txpipe-shop/thoth/blob/main/docs/DESIGN.md): architecture overview and flow
- [docs/kind-author-guide.md](https://github.com/txpipe-shop/thoth/blob/main/docs/kind-author-guide.md): how to add an attestor kind on top of this package
- [ADR 0003](https://github.com/txpipe-shop/thoth/blob/main/docs/adr/0003-colluding-attestors-out-of-scope.md): colluding attestors are out of scope
- [`@thoth/core`](https://github.com/txpipe-shop/thoth/tree/main/packages/core): `AttestorDescriptor`, `Attestation`, `AttestationInput`
- [`@thoth/attestor`](https://github.com/txpipe-shop/thoth/tree/main/packages/attestor): the attestor-side `Attestor.attest` that `AttestorTransport` mirrors
- [`@thoth/zk-tls`](https://github.com/txpipe-shop/thoth/tree/main/packages/zk-tls): the zkFetch kind, a client built on this package
- [`@thoth/contracts`](https://github.com/txpipe-shop/thoth/tree/main/packages/contracts): the on-chain registry that verifies the signatures positionally
