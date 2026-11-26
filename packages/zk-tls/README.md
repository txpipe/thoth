# @txpipe/thoth-zk-tls

The zkFetch attestor kind for Thoth, which turns [Reclaim](https://github.com/reclaimprotocol/attestor-core) evidence of an HTTPS fetch into a claim a Midnight contract can verify, for dApp developers who need an attested web fact and for the operators who run its attestors.

> **In development.** Thoth is unaudited and has [known security issues](https://github.com/txpipe/thoth/issues?q=is%3Aissue+is%3Aopen+label%3Asecurity). Don't use it to protect real value. The claim format may still change.

## Install

The package is not on npm. Build it from a checkout of this repo and install it by path:

```bash
git clone https://github.com/txpipe/thoth && cd thoth
npm install && npm run build
cd /path/to/your-app && npm install /path/to/thoth/packages/zk-tls
```

Once it is published, it installs as `@txpipe/thoth-zk-tls`. It needs `zod@^4.6.7` as a peer dependency.

It depends on [`re2`](https://github.com/uhop/node-re2), a native Node module. `npm install` downloads a prebuilt binary for common platforms and otherwise builds one, which needs a C++ toolchain. The prover and the policy schema refuse to run without it ([Regex engine](https://github.com/txpipe/thoth/blob/main/packages/zk-tls/docs/dapp-integration.md#regex-engine)).

## Usage

An operator builds an attestor from a signing key pair and the address of the Reclaim witness it trusts, then serves `attestor.attest(input)` to dApps ([attestor guide](https://github.com/txpipe/thoth/blob/main/packages/zk-tls/docs/attestor-guide.md)):

```ts
import { zkFetchAttestor } from '@txpipe/thoth-zk-tls/attestor';

const attestor = zkFetchAttestor({ id: 'attestor-a', keyPair, witnessAddress: '0x…' });
```

A dApp pins its attestors, fetches through each one's witness, and collects a threshold of signatures over one claim ([dApp guide](https://github.com/txpipe/thoth/blob/main/packages/zk-tls/docs/dapp-integration.md)):

```ts
import { buildTrustedSet } from '@txpipe/thoth-client';
import { jubjubVerifier } from '@txpipe/thoth-client/jubjub';
import { holderCommitmentOf } from '@txpipe/thoth-core/claim-context';
import { zkFetchBodyHashOf, type ZkFetchPolicy } from '@txpipe/thoth-zk-tls';
import { zkFetchClient } from '@txpipe/thoth-zk-tls/client';
import { zkFetchProver } from '@txpipe/thoth-zk-tls/prover';

const SENTINEL = '{"thoth":"ignored"}';

const policy: ZkFetchPolicy = {
  allowedHosts: ['api.github.com'],
  slots: [{ slot: 0, name: 'stars', parse: 'int' }],
  responseMatches: [{ type: 'regex', value: '"stargazers_count":\\s*(?<stars>\\d+)' }],
  responseRedactions: [{ regex: '"stargazers_count":\\s*\\d+' }],
  bodyPolicy: { sha256: zkFetchBodyHashOf(SENTINEL) }, // bind the body we send
};

const client = zkFetchClient.init({
  trusted: buildTrustedSet({
    registrySize: 3, // the contract's #M
    attestors: [
      { attestor: descriptorA, registryIndex: 0 },
      { attestor: descriptorB, registryIndex: 1 },
    ],
  }),
  transport, // how you reach each attestor; see the dApp guide
  verifier: jubjubVerifier,
  policy,
  appId, // 32 bytes; the contract seals zkFetchPolicyHashOf(policy)
  valueSlots: 1, // the contract's #V
  provers: {
    [descriptorA.id]: zkFetchProver({ witnessUrl: 'wss://witness-a.example/ws' }),
    [descriptorB.id]: zkFetchProver({ witnessUrl: 'wss://witness-b.example/ws' }),
  },
});

const now = Math.floor(Date.now() / 1000);
const attestment = await client.collect(
  { url: 'https://api.github.com/repos/txpipe/dolos', body: SENTINEL },
  {
    holder: holderCommitmentOf(holderSecret), // a fresh 32-byte secret per claim
    windowStart: BigInt(now - 60),
    windowEnd: BigInt(now + 60),
    expiresAt: Date.now() + 60_000,
    threshold: 2, // the contract's N
    attestorTimeoutMs: 20_000,
  },
);
```

`attestment.collected[i]` carries each signature with its registry slot; hand them to the contract as the dApp guide's [last section](https://github.com/txpipe/thoth/blob/main/packages/zk-tls/docs/dapp-integration.md#handing-it-to-the-contract) shows.

## Concepts

- [Attestor](https://github.com/txpipe/thoth/blob/main/CONTEXT.md#roles): verifies evidence under a policy and signs the claim. One instance serves any contract; the dApp assigns its registry slot.
- [Witness](https://github.com/txpipe/thoth/blob/main/CONTEXT.md#roles): the Reclaim process that runs the fetch and signs what it saw. Each attestor trusts exactly one, by address.
- [Prover](https://github.com/txpipe/thoth/blob/main/CONTEXT.md#roles): the client-side evidence source, `zkFetchProver`, one per attestor, pointed at that attestor's witness.
- [Policy](https://github.com/txpipe/thoth/blob/main/CONTEXT.md#the-claim): the host allowlist, the slot map, the [disclosure rules](https://github.com/txpipe/thoth/blob/main/CONTEXT.md#the-claim), and the [body policy](https://github.com/txpipe/thoth/blob/main/packages/zk-tls/docs/dapp-integration.md#body-policy). `zkFetchPolicyHashOf(policy)` is the claim's `policyHash`, which the contract seals.
- [Claim](https://github.com/txpipe/thoth/blob/main/CONTEXT.md#the-claim): what the attestors sign. Its [values](https://github.com/txpipe/thoth/blob/main/CONTEXT.md#the-claim) and [present](https://github.com/txpipe/thoth/blob/main/CONTEXT.md#the-claim) mask hold what the witness disclosed, slot by slot; [byte slots](https://github.com/txpipe/thoth/blob/main/CONTEXT.md#the-claim) carry fixed-width byte strings.
- [Subject](https://github.com/txpipe/thoth/blob/main/CONTEXT.md#the-claim): the request (method, host, path, body), each part hashed; `subjectHash` binds the claim to it. An empty body hashes to `sha256('')`, and the [body policy](https://github.com/txpipe/thoth/blob/main/packages/zk-tls/docs/dapp-integration.md#body-policy) decides whether it is allowed.
- [Holder](https://github.com/txpipe/thoth/blob/main/CONTEXT.md#the-claim): a per-claim commitment from `holderCommitmentOf(secret)`. Keep the secret for the contract witness.
- [Window](https://github.com/txpipe/thoth/blob/main/CONTEXT.md#the-claim): when the witnesses observed, not when the fact happened.
- [Trusted set](https://github.com/txpipe/thoth/blob/main/CONTEXT.md#signing-and-collection) and [attestment](https://github.com/txpipe/thoth/blob/main/CONTEXT.md#signing-and-collection): the dApp's pinned attestors, and the N-of-M set `collect` returns.

## Guarantees and limits

What the attestor checks before signing:

- The policy, the evidence and the proposed claim fit the attestor's input limits. Oversized input fails while it is parsed, before the law's `verify` step or the signature runs. Each operator can change any limit ([Input limits](https://github.com/txpipe/thoth/blob/main/packages/zk-tls/docs/attestor-guide.md#input-limits)); the defaults, `ZK_FETCH_DEFAULT_LIMITS`, are below. String lengths count UTF-16 code units.
  - Claim: 64 numeric slots and 64 byte slots.
  - Policy: 64 `allowedHosts` of up to 253 characters, one slot entry per claim slot with names up to 128 characters, 32 `responseMatches` and 32 `responseRedactions` with rule texts up to 4096 characters.
  - Evidence: `claim.parameters` up to 256 KiB, `claim.context` up to 1 MiB, `responseText` up to 4 MiB, and 256 characters for each other string.
- The witness's ECDSA signature over the Reclaim claim, and that the claim identifier matches its signed content.
- The witness address is the one the definition was created with, checked before the signature.
- The signed request carries no `{{param}}` template ([why](https://github.com/txpipe/thoth/blob/main/packages/zk-tls/docs/dapp-integration.md#building-the-request)).
- The attested URL is HTTPS on an allowed host. An `allowedHosts` entry admits that host and its subdomains on port 443 only. To allow another port, name it in the entry, as in `api.example.com:8443`. Case and a trailing dot do not change a match. The policy schema refuses an entry that is empty, carries a path or whitespace, or names a port outside 1–65535.
- The signed URL carries no `*`, including one its host parses to ([why](https://github.com/txpipe/thoth/blob/main/packages/zk-tls/docs/dapp-integration.md#building-the-request)).
- The signed request body carries no `*` and satisfies the policy's [body policy](https://github.com/txpipe/thoth/blob/main/packages/zk-tls/docs/dapp-integration.md#body-policy).
- The policy's regexes compile under RE2, the engine the prover runs them with ([Regex engine](https://github.com/txpipe/thoth/blob/main/packages/zk-tls/docs/dapp-integration.md#regex-engine)).
- Every slot `name` is declared as a named group by one of the policy's `regex` matches, as RE2 reads the regex, so a slot that could never be disclosed fails when the policy is parsed.
- The disclosure rules the witness signed equal the policy's, so a slot cannot be pointed at a different field than the policy intends. Array order, the order of a rule's keys, empty redaction keys and an absent array are inert; every other difference, including Reclaim's `invert` and `hash`, rejects.
- Every required slot is certifiable: disclosed and parseable under its rule and `length` pin. An optional slot that is absent or unparseable is signed unpresent.
- The witness's observation time falls inside the proposed window, bounds included.
- The context the witness signed carries the [claim context](https://github.com/txpipe/thoth/blob/main/CONTEXT.md#the-claim) digest of the policy, the signed request's subject, and the proposed holder and window ([ADR 0011](https://github.com/txpipe/thoth/blob/main/docs/adr/0011-evidence-binds-the-claim-context.md)).
- The proposed [salt](https://github.com/txpipe/thoth/blob/main/CONTEXT.md#the-claim) is that digest.
- The proposed `subjectHash` is the hash of the request the witness signed, and the proposed values are exactly what the evidence disclosed. The attestor then signs the claim it derived itself, so a client cannot have it certify a different reading.

What the client checks:

- A request whose `context` sets `thothClaimContext` is refused before any witness is contacted; the client reserves that key for the claim context digest.
- Every witness's evidence is for the requested origin, method, path, query and body, and was observed inside the window, or `proveReq` and `collect` refuse it before any attestor is contacted.
- `proveReq` requires every witness to yield one claim before any attestor is contacted, or fails with `witnesses disagree`. `collect` proves and attests per attestor and counts only signatures over one exact message, so disagreeing witnesses end in `ZkFetchThresholdError` with reason `threshold`.
- Each attestation's key is the pinned one, its claim is the proposal, its message encodes that claim, and its signature verifies. A forged response fails before submission.
- `collect` counts one signature per registry slot inside one exact-message group, starts `threshold` attempts, and contacts a spare only when the attempts in flight cannot reach the threshold any more. A spare that is never needed does not receive the request. Set `expiresAt` to at least twice `attestorTimeoutMs` after the start, so a spare can still prove after one attestor hangs.
- Evidence that carries a secret header value, as written, percent-encoded, or JSON-escaped, is refused before it reaches an attestor. A very short secret can match unrelated text and drop a healthy attestor as `secret`.
- The secret scan parses JSON strings recursively. If the nesting is deep enough that the scan cannot complete, the evidence is refused as `evidence`; it is never treated as clean. The exact depth depends on the JavaScript runtime.

When `collect` drops an attestor, its entry in `failures` names one reason:

| Reason        | What failed                                                                                                                                                                                      | What to do                                                                                                                                                                                                                                          |
| ------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `transport`   | The prover could not reach the witness, or the witness could not reach the source: a network error, a timeout, a proxy failure, a refused connection, or a TLS certificate or handshake failure. | Check the witness URL, and that the witness can reach the source. If the witness requires a signed auth request, also check that yours is well formed: the witness reports a malformed one the same way.                                            |
| `no-match`    | The response failed the policy's `responseRedactions` or `responseMatches` when the client checked it.                                                                                           | Check the policy against what the source returns.                                                                                                                                                                                                   |
| `evidence`    | Proving failed for another reason, such as a non-2xx status from the source, the witness refused the claim, or the evidence did not fit the request, the policy, the window or the slot counts.  | Check the request and the policy. The client checks the disclosure rules before the witness does, so a witness that refuses a claim usually runs another attestor-core version, has a skewed clock, or rejected the proof. Check the witness's log. |
| `secret`      | The evidence carried a secret header value.                                                                                                                                                      | Check that the response does not echo the secret and the prover redacts it. A very short secret can match unrelated text.                                                                                                                           |
| `attestation` | The attestor refused, or its answer did not verify.                                                                                                                                              | Check the attestor's logs and the trusted set's keys.                                                                                                                                                                                               |
| `timeout`     | The attempt passed `attestorTimeoutMs` or `expiresAt`.                                                                                                                                           | Raise the limits, or check the slow witness or attestor.                                                                                                                                                                                            |

A custom `ZkFetchProver` reports `transport` and `no-match` by throwing `ZkFetchProverError`. Any other error it throws becomes `evidence`. `proveReq` rethrows a prover's error without its message or cause: as a `ZkFetchProverError` with the same reason, or as an `Error` that names only the attestor whose prover failed.

What it does not check, and what your app must do:

- The window is not the exact fetch time: the fetch happened no earlier than about 10 minutes before `windowStart`. Do not read it as the time of the fact ([Window](https://github.com/txpipe/thoth/blob/main/CONTEXT.md#the-claim) explains why).
- `bodyPolicy: 'ignored'` does not bind the body the witness sent: a caller can send a body while every witness signs an empty one, including on a GET. Use it only when a body cannot change the endpoint's response at any layer ([Body policy](https://github.com/txpipe/thoth/blob/main/packages/zk-tls/docs/dapp-integration.md#body-policy)).
- The client does not re-verify the witness signature; each attestor does, and the contract enforces the threshold.
- Thoth can't check which engine a witness runs. A witness without `re2` falls back to RegExp. When that changes what it extracts, the witnesses disagree and the client fails closed, but a trusted set whose witnesses all lack `re2` agrees on RegExp's reading. Run every witness with `re2` ([attestor guide](https://github.com/txpipe/thoth/blob/main/packages/zk-tls/docs/attestor-guide.md#running-a-reclaim-witness)).
- `responseText` is the transcript as the client saw it. The witness does not sign it; the secret scan reads it, but no other check does.
- The secret header check cannot recognize every transformation of a secret. The prover must still redact.
- An attempt that times out keeps running in the background: Reclaim's `createClaimOnAttestor` takes no abort signal. Its late result is never counted.
- Errors from `proveReq` and `collect` carry no remote error text; a `collect` failure carries only its registry slot and reason.
- `threshold` is yours to set; the client cannot read the contract's N.
- The claim's values are not source-bound on-chain unless your circuit recomputes `subjectHash` from the subject fields (ADR 0001).
- Reusing a holder secret links claims. Thoth promises no cross-claim unlinkability (ADR 0004).
- Never disclose the salt or `claim.holder` in your own circuits: the holder is the salt's only secret input. Key holder state on the vault pseudonym (`holderOf`) instead.
- The nullifier does not stop the same fact from being claimed again under a fresh holder, even in the same window: a new fetch gets a new salt. If your app needs one claim per fact, keep your own set ([contracts limits](https://github.com/txpipe/thoth/blob/main/packages/contracts/README.md#guarantees-and-limits)).
- Every attestor in a trusted set must run the same witness version and behavior; an upstream change can split the set. Run the attestor guide's [live check](https://github.com/txpipe/thoth/blob/main/packages/zk-tls/docs/attestor-guide.md#live-check) before rotating.

## Design decisions

- **The attestor signs the claim it derives, not the one the client proposes.** The proposal only supplies `appId`, `holder`, the window and the slot counts; values, `subjectHash` and `salt` come from the evidence ([ADR 0001](https://github.com/txpipe/thoth/blob/main/docs/adr/0001-source-binding-by-in-circuit-subject-hash.md)).
- **The subject keeps the host as its own hashed field.** Your circuit can bind the source host while the path, which may name an account, stays private ([ADR 0001](https://github.com/txpipe/thoth/blob/main/docs/adr/0001-source-binding-by-in-circuit-subject-hash.md)).
- **The window is when the witnesses observed.** `collect` keeps it fixed across spares, because widening it would change the signed message and discard earlier signatures ([ADR 0005](https://github.com/txpipe/thoth/blob/main/docs/adr/0005-window-is-when-the-attestor-observed.md)).
- **You fix the holder and window before proving.** `proveReq` and `collect` take them up front, because every witness signs them through the claim context digest; evidence then yields a claim only for them ([ADR 0011](https://github.com/txpipe/thoth/blob/main/docs/adr/0011-evidence-binds-the-claim-context.md)).
- **The salt is the claim context digest the witnesses signed.** It commits to your holder commitment, which never reaches the ledger, so the nullifier cannot confirm a guessed value. It follows the holder and window you bind before proving, and changing it takes new evidence ([ADR 0012](https://github.com/txpipe/thoth/blob/main/docs/adr/0012-nullifier-hashes-a-secret-attestor-derived-salt.md)).
- **The claim does not commit to the Reclaim evidence.** You cannot audit a claim against its transcript offline; the claim commits to the values your app reads ([ADR 0007](https://github.com/txpipe/thoth/blob/main/docs/adr/0007-no-evidence-commitment.md)).
- **Byte rules decode the representation.** `hex` and `base64` fold only what carries no data, so separators and whitespace stay data; the [Byte slot](https://github.com/txpipe/thoth/blob/main/CONTEXT.md#the-claim) entry has the rules ([ADR 0010](https://github.com/txpipe/thoth/blob/main/docs/adr/0010-encoded-byte-rules.md)).
- **`int` reads decimal or `0x`/`0X`-prefixed hex.** One numeric rule covers both spellings, so a source that writes an unsigned integer as minimal-length hex needs no new parse rule; the policy's `responseMatches` regex must still match the hex text. The prefix is required, leading zeros are allowed, and the value must be below `2^64`. `hex` stays the byte rule and needs an even number of digits ([Numeric rules](https://github.com/txpipe/thoth/blob/main/packages/zk-tls/docs/dapp-integration.md#building-the-policy)).
- **The disclosure rules are part of the policy.** The client proves with the policy's rules, the attestor requires the signed rules to equal them, and the policy hash commits to them. A rule cannot use `{{param}}` templates, because the witness would sign the template and run the substitution.
- **Policy regexes are RE2.** The package depends on the native `re2` module and refuses to prove or parse a policy without it, so the prover and the witnesses run your regexes with one engine. Write them in [RE2 syntax](https://github.com/google/re2/wiki/Syntax). `re2` is a Node module, so the prover and the policy schema run only on Node.
- **A slot names a regex group.** The policy schema refuses a slot whose `name` no `regex` match declares as a named group, so a misnamed slot fails when you parse the policy, not at attest time after the witnesses ran. RE2 itself reports a regex's groups, so a group-like sequence that is escaped, in a character class or in `\Q…\E` doesn't count.
- **The signed request carries no `{{param}}` template.** The signed url, body, `geoLocation` and `proxySessionId` cannot contain `{{`, so put a per-user URL in the request as a concrete URL and don't use Reclaim's secret `paramValues` ([Building the request](https://github.com/txpipe/thoth/blob/main/packages/zk-tls/docs/dapp-integration.md#building-the-request)).
- **The policy decides how the request body is bound.** `bodyPolicy` is required and part of the policy hash, so there is no method-based default and every attestor enforces the same rule. Reclaim compares the sent body only when the signed body is non-empty, so you choose between a bound body (`non-empty` or a pin) and the explicit unbound `ignored` ([Body policy](https://github.com/txpipe/thoth/blob/main/packages/zk-tls/docs/dapp-integration.md#body-policy)).
- **One policy per trusted set.** N-of-M means N attestors signed the same message, so every attestor must enforce the same policy; different readings produce different messages and never count together. Which witness an attestor trusts is per instance, not part of the policy.
- **Each attestor sets its own input limits.** They are offchain config that bounds what a request costs the operator. A limit only refuses input and never changes the signed message, so attestors with different limits cost a trusted set liveness, not safety: a request that some attestors refuse may not reach the threshold. Agree on limits with your attestors, as you do on the witness version. The client and the exported schemas cap nothing.
- **One attestor instance serves any contract.** The slot counts come from each proposal, up to the instance's limits, and the registry slot from each dApp's trusted set (see [`@txpipe/thoth-attestor`](https://github.com/txpipe/thoth/tree/main/packages/attestor#design-decisions)).
- **The prover is its own entry point.** `@txpipe/thoth-zk-tls/prover` loads the Reclaim client libraries lazily, so a client-only build never pulls them. `@txpipe/thoth-zk-tls/client` imports neither those libraries nor `@txpipe/thoth-attestor`.

## License

AGPL-3.0-only: this package links Reclaim Protocol's [attestor-core](https://github.com/reclaimprotocol/attestor-core), which is AGPL-3.0-only. An app that incorporates this package must offer the combined work under AGPL; the rest of Thoth is Apache-2.0. If AGPL doesn't fit your app, don't include this package, or get a commercial license from Reclaim. Third-party code: attestor-core AGPL-3.0-only © Reclaim Protocol; [tls](https://github.com/reclaimprotocol/tls) MIT © CreatorOS Inc.

## Links

- [Thoth (repo root)](https://github.com/txpipe/thoth): overall architecture and docs
- [docs/DESIGN.md](https://github.com/txpipe/thoth/blob/main/docs/DESIGN.md): the architecture, the claim and its wire order
- [docs/kind-author-guide.md](https://github.com/txpipe/thoth/blob/main/docs/kind-author-guide.md): how to add a kind, with this package as the worked example
- [dApp guide](https://github.com/txpipe/thoth/blob/main/packages/zk-tls/docs/dapp-integration.md): client setup, requests, policies, and handing the attestment to the contract
- [attestor guide](https://github.com/txpipe/thoth/blob/main/packages/zk-tls/docs/attestor-guide.md): deploying an attestor, running a Reclaim witness, and the live check
- [`@txpipe/thoth-core`](https://github.com/txpipe/thoth/tree/main/packages/core): the claim, `claimToMessage` and `holderCommitmentOf`
- [`@txpipe/thoth-attestor`](https://github.com/txpipe/thoth/tree/main/packages/attestor): `KeyPair`, `Attestor`, `buildAttestor`
- [`@txpipe/thoth-client`](https://github.com/txpipe/thoth/tree/main/packages/client): `buildTrustedSet`, the transport, `resolveAttestation`
- [`@txpipe/thoth-contracts`](https://github.com/txpipe/thoth/tree/main/packages/contracts): the on-chain registry that verifies the signatures positionally
- [Reclaim attestor-core](https://github.com/reclaimprotocol/attestor-core): the witness this kind verifies
- [Reclaim zkFetch](https://github.com/reclaimprotocol/zk-fetch): the hosted-witness client; see the dApp guide's [hosted adapter](https://github.com/txpipe/thoth/blob/main/packages/zk-tls/docs/dapp-integration.md#reclaims-hosted-zkfetch-sdk)
