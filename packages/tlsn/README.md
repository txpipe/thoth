# @txpipe/thoth-tlsn

The tlsn@1 [kind](https://github.com/txpipe-shop/thoth/blob/main/CONTEXT.md#kinds): the zkFetch kind's policy, disclosure rules and client, with a [TLSNotary](https://tlsnotary.org) session as the evidence instead of a Reclaim witness. It is for dApp developers who want a choice of evidence for the same web fact, and for the operators who run its attestors and notaries. It is a prototype.

> **In development.** Thoth is unaudited and has [known security issues](https://github.com/txpipe-shop/thoth/issues?q=is%3Aissue+is%3Aopen+label%3Asecurity). Don't use it to protect real value. The claim format may still change.

## Install

The package is private and not published. Build it, and its native tool, from a checkout of this repo:

```bash
git clone https://github.com/txpipe-shop/thoth && cd thoth
npm install && npm run build
npm run build:native --workspace=packages/tlsn   # needs Rust; builds native/target/release/thoth-tlsn
```

The `thoth-tlsn` binary is the TLSNotary side: a notary, the MPC-TLS prover, and the presentation verifier. The attestor and the client call it as a subprocess.

## Usage

Write the policy exactly as you would for zkFetch. The same object is valid for both kinds:

```ts
import type { TlsnPolicy } from '@txpipe/thoth-tlsn';
import { tlsnPolicyHashOf } from '@txpipe/thoth-tlsn';
import { zkFetchPolicyHashOf } from '@txpipe/thoth-zk-tls';

const policy: TlsnPolicy = {
  allowedHosts: ['api.github.com'],
  slots: [{ slot: 0, name: 'stars', parse: 'int' }],
  responseMatches: [{ type: 'regex', value: '"stargazers_count":(?<stars>\\d+)' }],
  responseRedactions: [{ jsonPath: '$.stargazers_count' }],
  bodyPolicy: 'ignored',
};

// Seal the hash of each kind you accept. Each kind signs only its own.
const policyHashes = [tlsnPolicyHashOf(policy), zkFetchPolicyHashOf(policy)];
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

The client has `zkFetchClient`'s configuration and calls. Swap the prover, and add a `presentationVerifier`:

```ts
import { tlsnClient, tlsnProver } from '@txpipe/thoth-tlsn/client';
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
    'tlsn-github-1': tlsnProver({ binary: 'thoth-tlsn', notary: 'notary-1.example:7047' }),
    'tlsn-github-2': tlsnProver({ binary: 'thoth-tlsn', notary: 'notary-2.example:7047' }),
  },
});

const { claim, collected, failures } = await client.collect(
  {
    url: 'https://api.github.com/repos/txpipe-shop/thoth',
    secretHeaders: { Authorization: `Bearer ${token}` },
  },
  {
    holder: holderCommitmentOf(secret),
    windowStart,
    windowEnd,
    threshold: 2,
    expiresAt: Date.now() + 120_000,
    attestorTimeoutMs: 60_000,
  },
);
```

`client.proveReq(request, { holder, windowStart, windowEnd })` and `proof.attest(...ids)` work as they do for zkFetch.

## Concepts

- [Attestor](https://github.com/txpipe-shop/thoth/blob/main/CONTEXT.md#roles): verifies the presentation, reads the redacted response under the policy, and signs the claim.
- [Notary](https://github.com/txpipe-shop/thoth/blob/main/CONTEXT.md#roles): runs MPC-TLS with the prover and signs the attestation behind a presentation. It sees no plaintext. Each attestor pins one notary's key.
- [Presentation](https://github.com/txpipe-shop/thoth/blob/main/CONTEXT.md#roles): the evidence. It carries the notary-signed attestation, the server's identity, and the transcript bytes the prover reveals.
- [Disclosure rules](https://github.com/txpipe-shop/thoth/blob/main/CONTEXT.md#the-claim): `responseRedactions` choose what the prover reveals; `responseMatches` read the disclosed values from it. They mean what they mean under zkFetch.
- [Claim context](https://github.com/txpipe-shop/thoth/blob/main/CONTEXT.md#the-claim): the policy, subject, holder and window. The notary signs its digest as the `thoth.claim-context` attestation extension, and the digest is the claim's salt.
- [Subject](https://github.com/txpipe-shop/thoth/blob/main/CONTEXT.md#the-claim): `{ method, host, path, body }`, the same struct and hashes as zkFetch's.

## Guarantees and limits

The prover reveals what Reclaim's prover reveals: the request without its secret header values, and from the response the status line, the blank line that ends the headers, the `Date`, `Content-Type` and `Transfer-Encoding` lines, the chunk framing, and each redaction's slice. A `jsonPath` reveals the selected property's key and value. With no redactions, the whole response is revealed. The rest of the response never leaves the prover's machine.

The attestor checks, in order: the presentation verifies (notary signature, certificate chain to the trusted roots, transcript proof); the notary is the pinned one; the server is an allowed host or a subdomain of one; the request opens with `Host` (the server, no port) then `Connection: close`, and hides nothing but header values; the body satisfies `bodyPolicy`; the response is a 2xx; every response match holds on the redacted text, with hidden bytes as `*`, as the zkFetch witness runs them (RE2, `sgiu`); every required slot is certifiable; the notary signed this claim's claim context digest; its connection time is inside the window; and the proposal says exactly what the response shows.

Reveals and disclosed values match zkFetch byte for byte; `packages/zk-tls/test/tlsn-parity.test.ts` runs Reclaim's own prover and witness code against this package on the same bytes.

It differs from zkFetch where TLSNotary does:

- **`xPath` redactions are refused.** tlsn@1 reveals by `jsonPath` and `regex` only.
- **No ports.** TLSNotary attests the server name, not the TCP port, so `allowedHosts` entries carry no port and requests go to 443.
- **`bodyPolicy: 'ignored'` requires an empty body.** The attestor sees the body the prover sent, so there is no unbound body to send.
- **The attestor sees the redacted response.** Under zkFetch the witness sees it and the attestor sees only the disclosed values; here the notary sees nothing in clear and the attestor sees what the witness would. Each operator still sees the same redacted bytes.
- **The notary signs no other context.** A request `context` carries only the claim context digest.
- **TLS 1.2 with ECDHE over P-256 only.** MPC cost grows with the transcript: the prover's defaults are 4 KiB sent and 16 KiB received.

It shares zkFetch's limits: a hidden header value could hold a line break the attestor cannot see, a revealed `*` reads like a hidden byte, and notary collusion is out of scope (ADR 0003). Each attestor needs its own session, so the attestors converge only when the source returns the same values each time.

## Design decisions

- **Same policy, separate hash.** A policy hashes under its kind's law tag, so a contract that seals both hashes accepts a claim from either kind, but one threshold cannot mix the two. See [ADR 0015](https://github.com/txpipe-shop/thoth/blob/main/docs/adr/0015-tlsnotary-kind.md).
- **The attestor plays the witness.** It runs the zkFetch witness's response check on the revealed bytes itself, rather than trusting a notary to.
- **The reveal is chosen before the notary signs.** TLSNotary commits to revealed ranges before attesting, so `thoth-tlsn prove` pauses after the fetch and asks the TypeScript prover which ranges to commit.
- **The native tool is a subprocess.** TLSNotary is Rust and its JavaScript bindings target browsers, so the package calls the `thoth-tlsn` binary rather than linking it.

## Links

- [TLSNotary](https://tlsnotary.org) and its [Rust library](https://github.com/tlsnotary/tlsn), pinned at `v0.1.0-beta.1`
- [@txpipe/thoth-zk-tls](../zk-tls/README.md), the zkFetch kind this one mirrors
- [Adding an attestor kind](https://github.com/txpipe-shop/thoth/blob/main/docs/kind-author-guide.md)
- [ADR 0015: a TLSNotary kind](https://github.com/txpipe-shop/thoth/blob/main/docs/adr/0015-tlsnotary-kind.md)

## License

Apache-2.0. The `thoth-tlsn` tool links TLSNotary, which is MIT OR Apache-2.0.
