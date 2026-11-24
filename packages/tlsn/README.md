# @txpipe/thoth-tlsn

The tlsn@1 [kind](https://github.com/txpipe-shop/thoth/blob/main/CONTEXT.md#kinds) for Thoth, which attests a value from an HTTPS JSON response through a [TLSNotary](https://tlsnotary.org) session, for dApp developers who need web data and for the operators who run its attestors and notaries. It is a prototype next to the zkFetch kind.

> **In development.** Thoth is unaudited and has [known security issues](https://github.com/txpipe-shop/thoth/issues?q=is%3Aissue+is%3Aopen+label%3Asecurity). Don't use it to protect real value. The claim format may still change.

## Install

The package is private and not published. Build it, and its native tool, from a checkout of this repo:

```bash
git clone https://github.com/txpipe-shop/thoth && cd thoth
npm install && npm run build
npm run build:native --workspace=packages/tlsn   # needs Rust; builds native/target/release/thoth-tlsn
```

The `thoth-tlsn` binary is the TLSNotary side: a notary, a prover and the presentation verifier. The attestor and the client call it as a subprocess.

## Usage

Describe the response field you need as a policy, then hash it. The hash is the `policyHash` your contract seals:

```ts
import { tlsnPolicyHashOf, type TlsnPolicy } from '@txpipe/thoth-tlsn';

const policy: TlsnPolicy = {
  allowedHosts: ['api.github.com'],
  hiddenHeaders: ['authorization'], // values the attestors never see
  slots: [{ slot: 0, path: ['stargazers_count'], parse: 'int' }],
  bodyPolicy: 'empty',
};

const policyHash = tlsnPolicyHashOf(policy); // 32 bytes
```

Each operator runs one notary and one attestor that pins that notary's key:

```bash
thoth-tlsn notary --listen 0.0.0.0:7047 --signing-key "$NOTARY_KEY"   # prints its notaryKey
```

```ts
import { tlsnAttestor } from '@txpipe/thoth-tlsn/attestor';
import { nativePresentationVerifier } from '@txpipe/thoth-tlsn/verifier';

const attestor = tlsnAttestor({
  id: 'tlsn-github-1',
  keyPair, // the attestor's signing key, not the notary's
  notaryKey: { alg: 'k256', key: '03…' }, // what the notary printed
  verifier: nativePresentationVerifier({ binary: '/usr/local/bin/thoth-tlsn' }),
});
```

A dApp proves the request once per attestor, through that attestor's notary, and collects a threshold over one claim:

```ts
import { tlsnClient } from '@txpipe/thoth-tlsn/client';
import { nativeProver } from '@txpipe/thoth-tlsn/prover';
import { nativePresentationVerifier } from '@txpipe/thoth-tlsn/verifier';

const client = tlsnClient.init({
  trusted,
  transport,
  verifier: jubjubVerifier,
  policy,
  appId,
  valueSlots: 1,
  presentationVerifier: nativePresentationVerifier({ binary: 'thoth-tlsn' }),
  provers: {
    'tlsn-github-1': nativeProver({ binary: 'thoth-tlsn', notary: 'notary-1.example:7047' }),
    'tlsn-github-2': nativeProver({ binary: 'thoth-tlsn', notary: 'notary-2.example:7047' }),
  },
});

const { claim, collected } = await client.collect(
  {
    url: 'https://api.github.com/repos/txpipe-shop/thoth',
    secretHeaders: { Authorization: `Bearer ${token}` },
  },
  { holder: holderCommitmentOf(secret), windowStart, windowEnd, threshold: 2 },
);
```

## Concepts

- [Attestor](https://github.com/txpipe-shop/thoth/blob/main/CONTEXT.md#roles): verifies the presentation under the policy and signs the claim.
- [Notary](https://github.com/txpipe-shop/thoth/blob/main/CONTEXT.md#roles): runs MPC-TLS with the prover and signs the attestation behind a presentation. Each attestor pins one notary's key.
- [Presentation](https://github.com/txpipe-shop/thoth/blob/main/CONTEXT.md#roles): the evidence. It carries the notary-signed attestation, the server's identity and the revealed transcript.
- [Claim context](https://github.com/txpipe-shop/thoth/blob/main/CONTEXT.md#the-claim): the policy, subject, holder and window. The notary signs its digest as the `thoth.claim-context` attestation extension, and the digest is the claim's salt.
- [Subject](https://github.com/txpipe-shop/thoth/blob/main/CONTEXT.md#the-claim): `{ method, host, path, body }`, the same struct and hashes as the zkFetch kind for the same request on port 443.
- [Window](https://github.com/txpipe-shop/thoth/blob/main/CONTEXT.md#the-claim): the client proposes it; the notary's connection time must fall inside it.

## Guarantees and limits

The attestor checks, in order: the presentation verifies (notary signature, certificate chain to the trusted roots, transcript proof); the notary key is the pinned one; the server name is in `allowedHosts`; the request is one HTTP/1.1 request whose bytes are all revealed except the values of `hiddenHeaders`, whose `Host` is the server and whose body satisfies `bodyPolicy`; the whole response is revealed, uncompressed, with the policy's status; the notary signed exactly one extension, this claim's claim context digest; the notary's connection time is inside the window; and the proposal says exactly what the response shows.

It does not check:

- **The TCP port.** TLSNotary attests the server name, not the port. tlsn@1 requires the `Host` header without a port and assumes 443.
- **What a hidden header value holds.** A hidden value can contain line breaks the attestor cannot see, so it could add request headers. Name only the headers that must stay secret.
- **Response privacy from the attestors.** Each attestor sees the whole response. Claim values stay private on-chain, as with every kind, but not from the attestor set.
- **Notary independence.** An attestor trusts its notary as zkFetch trusts its witness; colluding operators are out of scope (ADR 0003).

TLSNotary speaks TLS 1.2 with ECDHE over P-256 only, and its MPC cost grows with the transcript size: the prover's defaults are 4 KiB sent and 16 KiB received.

Each attestor needs its own session, so the client proves once per attestor. The attestors converge only when the source returns the same values each time.

## Design decisions

- **Each attestor pins its own notary.** The notary plays the zkFetch witness's role, so the trust model and the client flow stay the same. See [ADR 0015](https://github.com/txpipe-shop/thoth/blob/main/docs/adr/0015-tlsnotary-kind.md).
- **The attestor reads the response itself.** TLSNotary discloses bytes, not fields, so tlsn@1 requires the whole response and parses it, rather than trusting a selective disclosure it cannot place.
- **Duplicate JSON keys are refused.** Parsers resolve them differently, so two attestors could read two values from one response.
- **The native tool is a subprocess.** TLSNotary is Rust and its JavaScript bindings target browsers, so the package calls the `thoth-tlsn` binary rather than linking it.

## Links

- [TLSNotary](https://tlsnotary.org) and its [Rust library](https://github.com/tlsnotary/tlsn), pinned at `v0.1.0-beta.1`
- [Adding an attestor kind](https://github.com/txpipe-shop/thoth/blob/main/docs/kind-author-guide.md)
- [ADR 0015: a TLSNotary kind](https://github.com/txpipe-shop/thoth/blob/main/docs/adr/0015-tlsnotary-kind.md)

## License

Apache-2.0. The `thoth-tlsn` tool links TLSNotary, which is MIT OR Apache-2.0.
