# Thoth Design

## Overview

A Midnight contract reads private data from the user's machine as witness
input. When that data is a fact from outside the chain, the contract needs two
things at once: assurance that the fact is true, and the fact kept private.

Thoth splits the work across three roles (see [`CONTEXT.md`](../CONTEXT.md#roles)):

- **Client**: runs in the dApp on the user's machine. It obtains evidence of
  the fact, collects the attestors' signatures, and submits them to the
  contract.
- **Attestor**: checks the evidence under a policy and, if satisfied, signs a
  claim derived from it with its own key. An attestor holds no app's policy,
  serves any app that reaches it, and never learns how a claim is used.
- **Contract**: pins the app's attestor keys and threshold at deploy, verifies
  the claim and its signatures in-circuit, and runs the app's predicate over
  the claim values.

Attestors certify facts, not decisions: a claim is a canonical statement of
what was observed, and the app defines the predicate over it. The same claim
can feed any number of predicates within the app it was signed for (its
`appId`).

One attestor alone would be almost no assurance, so each app pins M attestors
and requires N of them to sign the same claim. Colluding attestors are
[out of scope](#out-of-scope).

### Kinds

Attestors come in kinds, one per way of checking evidence. zkFetch, shipped as
[`@thoth/zk-tls`](../packages/zk-tls/README.md), checks a Reclaim zkFetch
proof that an HTTPS response was fetched and not forged; in that kind each
attestor trusts its own Reclaim witness. The contract knows nothing about
kinds: the claim's `policyHash` stands in for the kind ([ADR 0002](adr/0002-no-kind-on-chain-policy-hash.md)), so a new
kind needs no contract change. To add one, see
[kind-author-guide.md](kind-author-guide.md).

### What stays private

- **Credentials** (API keys, cookies, auth headers) never leave the user's
  machine; the fetch redacts them.
- **The evidence** goes to the attestors. It shows the disclosed values the
  claim is derived from, not the credentials or anything the fetch redacted.
- **The claim values** are private witness data in the contract and are not
  stored on-chain. The public nullifier hashes them with a secret salt, so it
  cannot confirm a guessed value ([ADR 0012](adr/0012-nullifier-hashes-a-secret-attestor-derived-salt.md));
  the [`@thoth/contracts` README](../packages/contracts/README.md#guarantees-and-limits)
  says what the ledger makes public.

Matching values alone do not prove where they came from. An app that needs
source binding recomputes `subjectHash` in-circuit from private subject fields
and pins only the fields it needs, such as the host ([ADR 0001](adr/0001-source-binding-by-in-circuit-subject-hash.md)).

## The claim

The claim is the same object everywhere (client, attestors, contract) and the
signed message covers all of it: anything the contract checks is a field of it.
The terms are defined in [`CONTEXT.md`](../CONTEXT.md#the-claim).

| Field                      | What it is                                                                                                                                                                   |
| -------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `version`                  | Wire version, `1` until a layout is deployed                                                                                                                                 |
| `appId`                    | The app the claim is for; the contract seals its own and rejects any other ([ADR 0013](adr/0013-contract-seals-its-app-id.md))                                               |
| `policyHash`               | Hash of the policy the attestors enforced; stands in for the kind ([ADR 0002](adr/0002-no-kind-on-chain-policy-hash.md))                                                     |
| `windowStart`, `windowEnd` | When the attestor observed, in Unix seconds ([ADR 0005](adr/0005-window-is-when-the-attestor-observed.md))                                                                   |
| `subjectHash`              | Circuit hash of what the claim is about ([ADR 0001](adr/0001-source-binding-by-in-circuit-subject-hash.md))                                                                  |
| `holder`                   | Per-claim commitment of the caller's secret ([ADR 0004](adr/0004-holder-is-per-claim-not-an-identity.md))                                                                    |
| `salt`                     | Secret the attestors derive from the evidence; the nullifier hashes it and the chain never sees it ([ADR 0012](adr/0012-nullifier-hashes-a-secret-attestor-derived-salt.md)) |
| `present`                  | One flag per value slot: `V` numeric slots, then `W` byte slots                                                                                                              |
| `values`                   | `V` positional `Uint<64>` measurements                                                                                                                                       |
| `byteValues`               | `W` positional 32-byte measurements (identifiers, strings) ([ADR 0009](adr/0009-byte-value-slots-in-the-claim.md))                                                           |

The window is when the attestor's witness looked, not when the fact happened,
and it is not the exact fetch time ([Window](../CONTEXT.md#the-claim)).

An absent slot must carry zero; a present slot may be zero. There is no nonce
and no kind code: the contract derives replay protection from the observation
identity ([ADR 0006](adr/0006-nullifier-keys-on-the-observation-identity.md)).

### Wire order

Attestors sign, and the contract rebuilds, seven field elements: the claim's
`version`, the layout's slot counts `V` and `W`, the claim's nullifier and its
`holder` ([ADR 0014](adr/0014-attestors-sign-the-nullifier.md)). The
nullifier is the SHA-256 of every other claim field, so every field reaches
the message, and the contract hashes the claim once for the signatures, replay
and the claims vault. `buildMessage` and `nullifierOf` in
[`attestation.compact`](../packages/contracts/attestation.compact) define
them; `claimToMessage` and `nullifierOf` in `@thoth/core/claim` mirror them,
and parity tests keep the two equal. A 32-byte value is two elements, byte 31,
then bytes 0–30 read little-endian (byte 0 least significant, the runtime's
`convertBytesToUint` convention), which is how the circuit holds it, so no
byte is sliced.

| Index | Field       | Encoding                                                 |
| ----- | ----------- | -------------------------------------------------------- |
| 0     | `version`   | `1`                                                      |
| 1     | `V`         | the numeric slot count; the contract writes its own `#V` |
| 2     | `W`         | the byte slot count; the contract writes its own `#W`    |
| 3, 4  | `nullifier` | byte 31, then bytes 0–30, of the SHA-256 below           |
| 5, 6  | `holder`    | byte 31, then bytes 0–30                                 |

The nullifier hashes the observation identity, `136 + 9*V + 33*W` bytes in
this order:

| Bytes                   | Field                                 | Encoding                               |
| ----------------------- | ------------------------------------- | -------------------------------------- |
| 0–31                    | `appId`                               | as is                                  |
| 32–63                   | `policyHash`                          | as is                                  |
| 64–95                   | `subjectHash`                         | as is                                  |
| 96–127                  | `salt`                                | as is                                  |
| 128–131                 | `windowStart`                         | Unix seconds, 4 bytes little-endian    |
| 132–135                 | `windowEnd`                           | Unix seconds, 4 bytes little-endian    |
| 8 each, from 136        | `values[0]` … `values[V-1]`           | 8 bytes little-endian; `0` when absent |
| 32 each, from 136+8V    | `byteValues[0]` … `byteValues[W-1]`   | as is; zero bytes when absent          |
| 1 each, from 136+8V+32W | `present[0]` … `present[V-1]`         | `1` measured, `0` absent               |
| 1 each, from 136+9V+32W | `bytePresent[0]` … `bytePresent[W-1]` | one flag per byte value                |

The identity's length fixes only `9*V + 33*W`, so two layouts can hash the same
bytes (`V = 11, W = 0` and `V = 0, W = 3`). Indexes 1 and 2 sign the layout:
the contract rebuilds them from its own `#V` and `#W`, so a message signed
under another layout fails verification. The sealed app id does not separate
layouts: every contract of one app seals the same one. With `W = 0` every byte
row disappears.

## Flow

```mermaid
sequenceDiagram
    participant Client
    participant API as 3rd Party API
    participant Attestor
    participant Contract

    Note over Client,API: Step 1: evidence per attestor (zkFetch: through its own witness)
    loop for each attestor's witness
        Client->>API: zkFetch request
        API-->>Client: zkFetch response
    end

    Note over Client,Attestor: Step 2: request attestation (N-of-M)
    loop for each attestor in the dApp's trusted set
        Client->>Attestor: policy + its witness's evidence + claim proposal
        Attestor-->>Client: signature over the claim
    end

    Note over Client,Contract: Step 3: submit to the contract
    Client->>Contract: claim + N signatures (private witness data)
    Note over Contract: verify
    Note over Contract: run predicate
```

1. In zkFetch the client fixes the holder and window, then fetches once per
   attestor, each through that attestor's witness, which signs the
   [claim context](../CONTEXT.md#the-claim) digest with its evidence
   ([ADR 0011](adr/0011-evidence-binds-the-claim-context.md)). The client
   keeps only what the witnesses agree on.
2. Each attestor verifies its own witness's evidence, checks that it signed
   the proposal's holder and window, derives the claim itself, salt included,
   and signs it.
   The client checks every signature and tags it with the attestor's registry
   slot, which the app assigned in its trusted set.
3. The contract verifies, in-circuit, the version, the policy hash, N valid
   signatures from distinct registry slots, each against its own slot's key,
   the absent slots, the holder secret, the window and replay
   ([ADR 0015](adr/0015-contract-verifies-n-named-signatures.md)). The
   [`@thoth/contracts` README](../packages/contracts/README.md#guarantees-and-limits)
   lists every check. It then vaults the claim under its nullifier, with a
   pseudonym of the holder secret
   ([ADR 0016](adr/0016-claims-vault-keyed-by-the-nullifier.md),
   [ADR 0017](adr/0017-vault-pseudonym-survives-network-upgrades.md)). Only
   then does the app's predicate run, opening the claim by its nullifier.

## Out of scope

- **Colluding attestors**: the threshold assumes the pinned operators are
  honest and independent ([ADR 0003](adr/0003-colluding-attestors-out-of-scope.md)).
- **Org or 1-of-1 attestation**: with a single authority, the registry and the
  threshold are redundant; a plain signature checked in a witness function
  does the whole job.
- **Judgment, voting, adjudication**: N attestors co-signing an opinion is
  consensus, not attesting a fact. It becomes in scope only if a trustworthy
  reference exists; then it is corroboration against a source.
- **Absolute price truth**: an attestor never vouches "the price is X"; at
  most it vouches a bounded predicate such as "|given − my source| ≤ margin".
- **Aggregation of partial attestations**: N attestors each covering a piece
  is invalid, because cheating on each small part cheats the whole claim.
- **Verifiable computation**: trusted execution and general zero-knowledge
  proofs, outside an attestation layer.
