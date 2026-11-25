# A TLSNotary kind that mirrors zkFetch

Status: proposed

The zkFetch kind's evidence comes from Reclaim's attestor-core, which is AGPL-3.0-only, so `@txpipe/thoth-zk-tls` is the one package that cannot be Apache-2.0. TLSNotary is MIT OR Apache-2.0 and attests the same kind of fact: one HTTPS session, with selective disclosure. This ADR proposes `tlsn@1`, built on TLSNotary `v0.1.0-beta.1`, as a second implementation of the zkFetch kind's behaviour: the same policy, disclosure rules, claim and client, with different evidence. A dApp chooses its evidence by sealing one kind's policy hash, or both. The contract does not change: it sees a kindless claim and accepts the policy hashes the app seals (ADR 0002, ADR 0008).

**The policy and client are zkFetch's.** A tlsn@1 policy has the `ZkFetchPolicy` shape and meaning: `allowedHosts` (exact or subdomain), slots read by named regex group, `responseMatches`, `responseRedactions` and `bodyPolicy`. One object passes both kinds' schemas. `tlsnClient` takes `zkFetchClient`'s configuration and calls, with the same options, failure reasons and errors, and one more field, the `presentationVerifier`. The policy hash still includes the law tag, so each kind's attestors sign only their own kind's hash and a threshold never mixes evidence models.

**Each attestor pins one notary, as each zkFetch attestor pins one witness.** TLSNotary's MPC runs between one prover and one verifier, so a session cannot serve a whole attestor set. The notary is that verifier, run by the attestor's operator, and it signs a portable attestation. The client proves once per attestor, so ADR 0003's collusion stance and the client flow match zkFetch's. TLSNotary removed its hosted notary and notary server in alpha.13, so `thoth-tlsn notary` is our own, built on its attestation crate.

**The attestor plays the zkFetch witness.** Reclaim's witness sees the redacted response and runs the response matches on it; the zkFetch attestor trusts the values it signs. A TLSNotary notary sees no plaintext, so the tlsn@1 attestor runs the witness's check itself on the bytes the presentation reveals: the status must be 2xx, hidden bytes read as `*`, chunked bodies are de-chunked, and the matches run under RE2 with Reclaim's `sgiu` flags through the same `re2` module. Each operator sees the same redacted bytes as under zkFetch; the attestor no longer has to trust anyone for the extraction.

**The prover reveals what Reclaim's prover reveals.** The request is revealed except secret header values, and opens with `Host` then `Connection: close`, the prefix Reclaim's witness requires. From the response, the prover reveals the status line, the blank line ending the headers, the `Date`, `Content-Type` and `Transfer-Encoding` lines, the chunk framing, and each redaction's slice, with `jsonPath` resolved by `jsonpath-plus` as Reclaim does. A parity test in the zk-tls package runs Reclaim's own `getResponseRedactions` and `assertValidProviderReceipt` against tlsn@1 on the same bytes and requires identical reveals and disclosed values. `xPath` redactions are refused rather than approximated.

**The reveal is fixed before the notary signs.** TLSNotary beta.1 commits to revealed ranges with hash commitments, which can only be opened whole, so the ranges must be known before the attestation. `thoth-tlsn prove` therefore pauses after the fetch, hands the plaintext to the TypeScript prover over a pipe, and commits exactly the ranges it returns. The plaintext never leaves the prover's machine, and all disclosure logic stays in TypeScript next to the other kinds' laws.

**The notary signs the claim context digest as an attestation extension.** The notary accepts exactly one extension, `thoth.claim-context`, 32 bytes. That keeps ADR 0011: a presentation signed for one holder and window yields no claim for another. The digest is the salt, as in ADR 0012.

**The window is the notary's clock.** The notary records the connection time from its own clock when it sees the server's hello. The attestor checks that time falls inside the proposed window, as ADR 0005 reads for zkFetch.

**The subject matches zkFetch's.** `{ method, host, path, body }` with the same hashes, so an app binding the source in-circuit (ADR 0001) binds it the same way under either kind. TLSNotary authenticates the server name but not the TCP port, so tlsn@1 refuses ports in `allowedHosts` and requests.

**The native side is a subprocess.** TLSNotary is Rust; its JavaScript package targets browsers and does not run in Node. The package calls the `thoth-tlsn` binary for notarizing, proving and verifying.

Open before this leaves prototype: an audit of the request and response readers, notary limits on transcript size, `xPath` support, and whether the parse rules move into `@txpipe/thoth-core`, where both web kinds could share them.
