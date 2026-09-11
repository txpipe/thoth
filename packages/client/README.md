# @thoth/client

Client-side base for the Thoth N-of-M attestation system.

Thoth lets Midnight contracts accept externally attested information with ZK
privacy. `@thoth/client` is the **generic dApp-side base**: the types and
collection routine a client uses to address the attestors in its trusted set
and assemble the N-of-M signature set — with none of the key-bearing or host
machinery, and no dependency on any particular attestor kind or signature
scheme.

Kind-specific SDKs (e.g. a zkTLS client) build *on top* of this package: they
wire a concrete transport and kind-typed trusted set, and add their own
prove/attest ergonomics.

## Install

```bash
npm install @thoth/client
```

## What's in it

- `TrustedSet<D, PK>` — the client's pinned attestors, in **on-chain
  registry-slot order**. Each member is an
  [`AttestorDescriptor`](https://github.com/txpipe-shop/thoth/tree/main/packages/core):
  `id`, its keyless `definition`, its `publicKey`, and its `registryIndex`.
- `AttestorTransport<D, PK, S>` — the seam between the client and a remote
  attestor: `request(attestor, input): Promise<Attestation>`. This package
  declares the seam only; a kind SDK or the app supplies the concrete transport
  (HTTP, in-process, mock). The host-side mirror is `Attestor.attest` in
  `@thoth/attestor` — both agree through `@thoth/core` types.
- `collectAttestations({ trusted, threshold, input, transport })` — fires a
  request at **every** attestor in the trusted set in parallel, keeps the
  attestations that pass structural checks (public key matches the descriptor,
  all collected sign the same message), and **throws if fewer than `threshold`
  (#N) valid attestations are collected**. The raw `input` is forwarded as-is —
  the attestor is the law.
- `AttestationBundle<C, Msg, PK, S>` — the positional submission payload:
  `claim`, `message`, and slot-aligned `signatures`/`publicKeys` vectors
  (`null` where a slot did not vouch), plus the vouching `registryIndexes`.
  `signatures[i]` lines up with the on-chain registry's positional verification.
- Errors: `ThresholdNotMetError`, `AttestorUnavailableError`,
  `AttestationMismatchError`.

## Usage

```ts
import { collectAttestations, type TrustedSet } from '@thoth/client';

const trusted: TrustedSet<MyDefinition, MyPublicKey> = {
  attestors: [descriptor0, descriptor1, descriptor2], // registry slots 0..2
};

const bundle = await collectAttestations({
  trusted,
  threshold: 2, // N-of-M: 2-of-3
  input: { policy, evidence, claim }, // raw, forwarded as-is
  transport: myTransport, // AttestorTransport instance from your kind SDK
});

// bundle.signatures[i] is the signature from registry slot i (null if absent)
```

The client does **not** verify signatures — the on-chain contract is the
verifier, and it checks them positionally against the pinned registry keys.

## Out of scope

- Off-chain signature verification (the contract verifies)
- Kind-specific logic: proof generation, policy validation, string-named
  attestor endpoints (`attest("endpoint", …)`) — those live in the kind SDK
  (e.g. `@thoth/zkTLS`) on top of this package
- Claim construction and input validation (the attestor's `verify` is the law)

## Links

- [Thoth (repo root)](https://github.com/txpipe-shop/thoth) — overall architecture and docs
- [docs/DESIGN.md](https://github.com/txpipe-shop/thoth/blob/main/docs/DESIGN.md) — the registry-slot positional design
- [`@thoth/core`](https://github.com/txpipe-shop/thoth/tree/main/packages/core) — `AttestorDescriptor`, `Attestation`, `AttestationInput`
- [`@thoth/attestor`](https://github.com/txpipe-shop/thoth/tree/main/packages/attestor) — the host-side `Attest`/`Attestor` these types mirror
- [`@thoth/contracts`](https://github.com/txpipe-shop/thoth/tree/main/packages/contracts) — the on-chain registry that verifies the signatures positionally