# A TLSNotary kind next to zkFetch

Status: proposed

The zkFetch kind's evidence comes from Reclaim's attestor-core, which is AGPL-3.0-only, so `@txpipe/thoth-zk-tls` is the one package that cannot be Apache-2.0. TLSNotary is MIT OR Apache-2.0 and attests the same kind of fact: one HTTPS session, with selective disclosure. This ADR proposes `tlsn@1`, a kind built on TLSNotary `v0.1.0-beta.1`, as a prototype next to zkFetch, not a replacement. The contract does not change: it sees a kindless claim and accepts a policy hash the app seals (ADR 0002, ADR 0008).

**Each attestor pins one notary, as each zkFetch attestor pins one witness.** TLSNotary's MPC runs between one prover and one verifier, so a session cannot serve a whole attestor set. The notary is that verifier, run by the attestor's operator, and it signs a portable attestation. The attestor checks the notary's key before anything else. The client proves once per attestor, so the trust model, ADR 0003's collusion stance and the client flow match zkFetch's. TLSNotary removed its hosted notary and notary server in alpha.13, so `thoth-tlsn notary` is our own, built on its attestation crate.

**The notary signs the claim context digest as an attestation extension.** TLSNotary attestations carry prover-requested extensions that the notary validates and signs. The notary accepts exactly one, `thoth.claim-context`, 32 bytes. That keeps ADR 0011: a presentation signed for one holder and window yields no claim for another. The digest is the salt, as in ADR 0012, so the nullifier stays unguessable.

**The window is the notary's clock.** The notary records the connection time from its own clock when it sees the server's hello, not a time the prover supplies. The client proposes the window and the attestor checks that time falls inside it, as ADR 0005 reads for zkFetch.

**The attestor parses the whole response.** Reclaim's witness runs the policy's regexes and signs what they extract. TLSNotary discloses byte ranges. With hidden bytes around them, the attestor cannot tell which field a revealed range belongs to, and a prover chooses what to hide. tlsn@1 therefore requires every received byte revealed, parses one HTTP/1.1 response and its JSON body itself, and refuses duplicate keys. The cost is privacy from the attestor set: each attestor sees the whole response. Narrowing that needs a disclosure the attestor can place, such as a commitment to the JSON structure or a ZK predicate over the transcript, and is left open.

**The request is revealed except named header values.** The policy's `hiddenHeaders` lists the headers whose values may stay hidden, such as `authorization`. Every other request byte is revealed, so the attestor reads the method, target and body for the subject. A hidden value can hold a line break the attestor cannot see, the same exposure zkFetch has with secret headers.

**The subject matches zkFetch's.** `{ method, host, path, body }` with the same hashes, so an app binding the source host in-circuit (ADR 0001) binds it the same way under either kind. TLSNotary authenticates the server name but not the TCP port, so tlsn@1 accepts only a `Host` without a port.

**The native side is a subprocess.** TLSNotary is Rust; its JavaScript package targets browsers and does not run in Node. The package calls a small `thoth-tlsn` binary for notarizing, proving and verifying, and keeps every policy decision in TypeScript, next to the other kinds' laws.

Open before this leaves prototype: an audit of the request and response parsers, a disclosure the attestor can place, notary limits on transcript size, and whether the parse rules move into `@txpipe/thoth-core`, where both web kinds could share them.
