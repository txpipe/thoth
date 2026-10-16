# @thoth/zk-tls

The zkFetch attestor kind for Thoth, which turns [Reclaim](https://github.com/reclaimprotocol/attestor-core) evidence of an HTTPS fetch into a claim a Midnight contract can verify, for dApp developers who need an attested web fact and for the operators who run its attestors.

> **In development.** Thoth is unaudited and has [known security issues](https://github.com/txpipe-shop/thoth/issues?q=is%3Aissue+is%3Aopen+label%3Asecurity). Don't use it to protect real value. The claim format may still change.

## Install

The package is not on npm. Build it from a checkout of this repo and install it by path:

```bash
git clone https://github.com/txpipe-shop/thoth && cd thoth
npm install && npm run build
cd /path/to/your-app && npm install /path/to/thoth/packages/zk-tls
```

Its package name is `@thoth/zk-tls`; that name may change until the npm scope is settled.

## Usage

An operator builds an attestor from a signing key pair and the address of the Reclaim witness it trusts, then serves `attestor.attest(input)` to dApps ([attestor guide](https://github.com/txpipe-shop/thoth/blob/main/packages/zk-tls/docs/attestor-guide.md)):

```ts
import { zkFetchAttestor } from '@thoth/zk-tls/attestor';

const attestor = zkFetchAttestor({ id: 'attestor-a', keyPair, witnessAddress: '0x…' });
```

A dApp pins its attestors, fetches through each one's witness, and collects a threshold of signatures over one claim ([dApp guide](https://github.com/txpipe-shop/thoth/blob/main/packages/zk-tls/docs/dapp-integration.md)):

```ts
import { buildTrustedSet } from '@thoth/client';
import { jubjubVerifier } from '@thoth/client/jubjub';
import { holderCommitmentOf } from '@thoth/core/claim-context';
import type { ZkFetchPolicy } from '@thoth/zk-tls';
import { zkFetchClient } from '@thoth/zk-tls/client';
import { zkFetchProver } from '@thoth/zk-tls/prover';

const policy: ZkFetchPolicy = {
  allowedHosts: ['api.github.com'],
  slots: [{ slot: 0, name: 'stars', parse: 'int' }],
  responseMatches: [{ type: 'regex', value: '"stargazers_count":\\s*(?<stars>\\d+)' }],
  responseRedactions: [{ regex: '"stargazers_count":\\s*\\d+' }],
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
  { url: 'https://api.github.com/repos/txpipe/dolos' },
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

`attestment.collected[i]` carries each signature with its registry slot; hand them to the contract as the dApp guide's [last section](https://github.com/txpipe-shop/thoth/blob/main/packages/zk-tls/docs/dapp-integration.md#handing-it-to-the-contract) shows.

## Concepts

- [Attestor](https://github.com/txpipe-shop/thoth/blob/main/CONTEXT.md#roles): verifies evidence under a policy and signs the claim. One instance serves any contract; the dApp assigns its registry slot.
- [Witness](https://github.com/txpipe-shop/thoth/blob/main/CONTEXT.md#roles): the Reclaim process that runs the fetch and signs what it saw. Each attestor trusts exactly one, by address.
- [Prover](https://github.com/txpipe-shop/thoth/blob/main/CONTEXT.md#roles): the client-side evidence source, `zkFetchProver`, one per attestor, pointed at that attestor's witness.
- [Policy](https://github.com/txpipe-shop/thoth/blob/main/CONTEXT.md#the-claim): the host allowlist, the slot map, and the [disclosure rules](https://github.com/txpipe-shop/thoth/blob/main/CONTEXT.md#the-claim). `zkFetchPolicyHashOf(policy)` is the claim's `policyHash`, which the contract seals.
- [Claim](https://github.com/txpipe-shop/thoth/blob/main/CONTEXT.md#the-claim): what the attestors sign. Its [values](https://github.com/txpipe-shop/thoth/blob/main/CONTEXT.md#the-claim) and [present](https://github.com/txpipe-shop/thoth/blob/main/CONTEXT.md#the-claim) mask hold what the witness disclosed, slot by slot; [byte slots](https://github.com/txpipe-shop/thoth/blob/main/CONTEXT.md#the-claim) carry fixed-width byte strings.
- [Subject](https://github.com/txpipe-shop/thoth/blob/main/CONTEXT.md#the-claim): the request (method, host, path, body), each part hashed; `subjectHash` binds the claim to it.
- [Holder](https://github.com/txpipe-shop/thoth/blob/main/CONTEXT.md#the-claim): a per-claim commitment from `holderCommitmentOf(secret)`. Keep the secret for the contract witness.
- [Window](https://github.com/txpipe-shop/thoth/blob/main/CONTEXT.md#the-claim): when the witnesses observed, not when the fact happened.
- [Trusted set](https://github.com/txpipe-shop/thoth/blob/main/CONTEXT.md#signing-and-collection) and [attestment](https://github.com/txpipe-shop/thoth/blob/main/CONTEXT.md#signing-and-collection): the dApp's pinned attestors, and the N-of-M set `collect` returns.

## Guarantees and limits

What the attestor checks before signing:

- The witness's ECDSA signature over the Reclaim claim, and that the claim identifier matches its signed content.
- The witness address is the one the instance was built with.
- The signed request carries no `{{param}}` template ([why](https://github.com/txpipe-shop/thoth/blob/main/packages/zk-tls/docs/dapp-integration.md#building-the-request)).
- The attested URL is HTTPS on an allowed host.
- The disclosure rules the witness signed equal the policy's, so a slot cannot be pointed at a different field than the policy intends. Array order, the order of a rule's keys, empty redaction keys and an absent array are inert; every other difference, including Reclaim's `invert` and `hash`, rejects.
- Every required slot is certifiable: disclosed and parseable under its rule and `length` pin. An optional slot that is absent or unparseable is signed unpresent.
- The witness's observation time falls inside the proposed window, bounds included.
- The context the witness signed carries the [claim context](https://github.com/txpipe-shop/thoth/blob/main/CONTEXT.md#the-claim) digest of the policy, the signed request's subject, and the proposed holder and window ([ADR 0011](https://github.com/txpipe-shop/thoth/blob/main/docs/adr/0011-evidence-binds-the-claim-context.md)).
- The proposed `subjectHash` is the hash of the request the witness signed, and the proposed values are exactly what the evidence disclosed. The attestor then signs the claim it derived itself, so a client cannot have it certify a different reading.

What the client checks:

- A request whose `context` sets `thothClaimContext` is refused before any witness is contacted; the client reserves that key for the claim context digest.
- Every witness's evidence is for the requested origin, method, path, query and body, and was observed inside the window, or `proveReq` and `collect` refuse it before any attestor is contacted.
- `proveReq` requires every witness to yield one claim before any attestor is contacted, or fails with `witnesses disagree`. `collect` proves and attests per attestor and counts only signatures over one exact message, so disagreeing witnesses end in `ZkFetchThresholdError` with reason `threshold`.
- Each attestation's key is the pinned one, its claim is the proposal, its message encodes that claim, and its signature verifies. A forged response fails before submission.
- `collect` counts one signature per registry slot inside one exact-message group, starts `threshold` attempts, and contacts a spare only when the attempts in flight cannot reach the threshold any more. A spare that is never needed does not receive the request. Set `expiresAt` to at least twice `attestorTimeoutMs` after the start, so a spare can still prove after one attestor hangs.
- Evidence that carries a secret header value, as written, percent-encoded, or JSON-escaped, is refused before it reaches an attestor. A very short secret can match unrelated text and drop a healthy attestor as `secret`.

What it does not check, and what your app must do:

- The window is not the exact fetch time: the fetch happened no earlier than about 10 minutes before `windowStart`. Do not read it as the time of the fact ([Window](https://github.com/txpipe-shop/thoth/blob/main/CONTEXT.md#the-claim) explains why).
- The client does not re-verify the witness signature; each attestor does, and the contract enforces the threshold.
- `responseText` is the transcript as the client saw it. The witness does not sign it, and no check reads it.
- The secret header check cannot recognize every transformation of a secret. The prover must still redact.
- An attempt that times out keeps running in the background: Reclaim's `createClaimOnAttestor` takes no abort signal. Its late result is never counted.
- Errors carry registry slots and step reasons, never remote error text.
- `threshold` is yours to set; the client cannot read the contract's N.
- The claim's values are not source-bound on-chain unless your circuit recomputes `subjectHash` from the subject fields (ADR 0001).
- Reusing a holder secret links claims. Thoth promises no cross-claim unlinkability (ADR 0004).
- Every attestor in a trusted set must run the same witness version and behavior; an upstream change can split the set. Run the attestor guide's [live check](https://github.com/txpipe-shop/thoth/blob/main/packages/zk-tls/docs/attestor-guide.md#live-check) before rotating.

## Design decisions

- **The attestor signs the claim it derives, not the one the client proposes.** The proposal only supplies `appId`, `holder`, the window and the slot counts; values and `subjectHash` come from the evidence ([ADR 0001](https://github.com/txpipe-shop/thoth/blob/main/docs/adr/0001-source-binding-by-in-circuit-subject-hash.md)).
- **The subject keeps the host as its own hashed field.** Your circuit can bind the source host while the path, which may name an account, stays private ([ADR 0001](https://github.com/txpipe-shop/thoth/blob/main/docs/adr/0001-source-binding-by-in-circuit-subject-hash.md)).
- **The window is when the witnesses observed.** `collect` keeps it fixed across spares, because widening it would change the signed message and discard earlier signatures ([ADR 0005](https://github.com/txpipe-shop/thoth/blob/main/docs/adr/0005-window-is-when-the-attestor-observed.md)).
- **You fix the holder and window before proving.** `proveReq` and `collect` take them up front, because every witness signs them through the claim context digest; evidence then yields a claim only for them ([ADR 0011](https://github.com/txpipe-shop/thoth/blob/main/docs/adr/0011-evidence-binds-the-claim-context.md)).
- **The claim does not commit to the Reclaim evidence.** You cannot audit a claim against its transcript offline; the claim commits to the values your app reads ([ADR 0007](https://github.com/txpipe-shop/thoth/blob/main/docs/adr/0007-no-evidence-commitment.md)).
- **Byte rules decode the representation.** `hex` and `base64` fold only what carries no data, so separators and whitespace stay data; the [Byte slot](https://github.com/txpipe-shop/thoth/blob/main/CONTEXT.md#the-claim) entry has the rules ([ADR 0010](https://github.com/txpipe-shop/thoth/blob/main/docs/adr/0010-encoded-byte-rules.md)).
- **The disclosure rules are part of the policy.** The client proves with the policy's rules, the attestor requires the signed rules to equal them, and the policy hash commits to them. A rule cannot use `{{param}}` templates, because the witness would sign the template and run the substitution.
- **The signed request carries no `{{param}}` template.** The signed url, body, `geoLocation` and `proxySessionId` cannot contain `{{`, so put a per-user URL in the request as a concrete URL and don't use Reclaim's secret `paramValues` ([Building the request](https://github.com/txpipe-shop/thoth/blob/main/packages/zk-tls/docs/dapp-integration.md#building-the-request)).
- **One policy per trusted set.** N-of-M means N attestors signed the same message, so every attestor must enforce the same policy; different readings produce different messages and never count together. Which witness an attestor trusts is per instance, not part of the policy.
- **One attestor instance serves any contract.** The slot counts come from each proposal, and the registry slot from each dApp's trusted set (see [`@thoth/attestor`](https://github.com/txpipe-shop/thoth/tree/main/packages/attestor#design-decisions)).
- **The prover is its own entry point.** `@thoth/zk-tls/prover` loads the Reclaim client libraries lazily, so a client-only build never pulls them. `@thoth/zk-tls/client` imports neither those libraries nor `@thoth/attestor`.

## Links

- [Thoth (repo root)](https://github.com/txpipe-shop/thoth): overall architecture and docs
- [docs/DESIGN.md](https://github.com/txpipe-shop/thoth/blob/main/docs/DESIGN.md): the architecture, the claim and its wire order
- [docs/kind-author-guide.md](https://github.com/txpipe-shop/thoth/blob/main/docs/kind-author-guide.md): how to add a kind, with this package as the worked example
- [dApp guide](https://github.com/txpipe-shop/thoth/blob/main/packages/zk-tls/docs/dapp-integration.md): client setup, requests, policies, and handing the attestment to the contract
- [attestor guide](https://github.com/txpipe-shop/thoth/blob/main/packages/zk-tls/docs/attestor-guide.md): deploying an attestor, running a Reclaim witness, and the live check
- [`@thoth/core`](https://github.com/txpipe-shop/thoth/tree/main/packages/core): the claim, `claimToMessage` and `holderCommitmentOf`
- [`@thoth/attestor`](https://github.com/txpipe-shop/thoth/tree/main/packages/attestor): `KeyPair`, `Attestor`, `buildAttestor`
- [`@thoth/client`](https://github.com/txpipe-shop/thoth/tree/main/packages/client): `buildTrustedSet`, the transport, `resolveAttestation`
- [`@thoth/contracts`](https://github.com/txpipe-shop/thoth/tree/main/packages/contracts): the on-chain registry that verifies the signatures positionally
- [Reclaim attestor-core](https://github.com/reclaimprotocol/attestor-core): the witness this kind verifies
- [Reclaim zkFetch](https://github.com/reclaimprotocol/zk-fetch): the hosted-witness client; see the dApp guide's [hosted adapter](https://github.com/txpipe-shop/thoth/blob/main/packages/zk-tls/docs/dapp-integration.md#reclaims-hosted-zkfetch-sdk)
