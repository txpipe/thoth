# Deploying a zkFetch attestor

The host side of the zkFetch kind: build an attestor instance, give it the
witness address and the policy it enforces.
See the [package README](../README.md) for what the package exports and
[dapp-integration.md](dapp-integration.md) for the dApp side.

## Building an instance

An attestor instance is a `KeyPair` and the public address of the Reclaim
witness the operator runs. The key pair comes from the signature scheme's key
package and is held by `@thoth/attestor`'s `AttestorSigner`; nothing in this
package touches a private key.

```ts
import { zkFetchAttestor } from '@thoth/zk-tls/attestor';

const attestor = zkFetchAttestor({
  id: 'zkFetch-strava-1',
  keyPair, // the attestor's signing key, not the witness's
  witnessAddress: '0x…the public address of your Reclaim witness…',
});
```

The instance takes no registry slot. Its signed message binds no slot,
registry, or contract, so one instance serves any app. Each app places the
attestor's public key in its own registry and records that slot in its
client-side trusted set; see [dapp-integration.md](dapp-integration.md).

`witnessAddress` is the public Ethereum address of the operator's own Reclaim
witness. The instance compares addresses case-insensitively and rejects evidence
signed by a different witness. Replace existing `witnessKey` inputs with this
address. The attestor process must never receive, load, or derive from the
witness private key. Obtain the address outside the attestor process, for example
from the witness's `/address` endpoint:

```bash
curl --fail http://localhost:8001/address
```

Copy the response's `address` field into `witnessAddress`. The local startup
script below also prints each witness's address. An operator
with access to the witness key can alternatively run
`cast wallet address --private-key …` on the witness host, then pass only the
resulting address to the attestor. Do not load the witness key from the
attestor's environment; configure each instance with its own public address.

The requested value-slot count is implicit in each claim's `values.length`.
`present` must have the same length, and every policy slot index must fit within
that count. These checks run before proof verification. Claim derivation uses
this requested count and fills unused positions with `present = false` and
`value = 0`, regardless of their proposed contents.

One attestor instance and signing key can serve contracts with different slot
counts. Each dApp configures its client for its contract's `#V`, and that contract
enforces the fixed layout it accepts. Attestor instances take no `valueSlots`
configuration; standalone definitions use `createZkFetchDefinition()`.

## The attest flow

The dApp sends the raw input over the transport; the attestor parses it with
its own schemas, checks array lengths and policy slot bounds, and runs the full
check before signing:

1. `verifyZkFetchProof(evidence)` re-verifies the Reclaim witness's ECDSA
   signature over the claim, checks the claim identifier against its signed
   content, and extracts the values it disclosed. It leaves the supplied evidence
   unchanged even when Reclaim canonicalizes the context during verification.
2. `assertEvidenceMatchesPolicy(verified, policy)` checks the attested URL
   against the host allowlist and requires every required slot to be certifiable.
   Captured `responseText` is untrusted, client-supplied transport output; the
   witness signature does not authenticate it, so policy checks do not use it.
3. `assertObservationInWindow({ claim, verified })` requires the witness's own
   observation to fall inside the client-proposed window, bounds included.
   The contract bounds the window's length and checks it against block time.
4. `assertClaimMatchesSubject({ claim, verified })` derives the subject hash
   from the request the witness signed and requires the proposal to carry it.
5. `assertClaimMatchesDisclosures({ claim, disclosures, policy })` enforces
   that the client-proposed claim says exactly what the evidence disclosed.

After those checks, `attestor.attest` also rejects evidence whose signing
witness is not the instance's own `witnessAddress`. Only then does it sign the
attestor-derived claim: values and present bits from the disclosed values,
the signed request's subject hash as `subjectHash`, and the hash of its own
policy as `policyHash`. It takes `appId`, the window, and the per-claim holder
commitment from the proposal.

The attestor derives its own claim rather than trusting the proposal, so a
client cannot make it certify a reading the evidence does not support.

## Running a Reclaim witness

The prover needs a witness to run against. Self-host one from the
[`attestor-core`](https://github.com/reclaimprotocol/attestor-core) repo:

```bash
git clone --depth 1 https://github.com/reclaimprotocol/attestor-core
cd attestor-core && npm install
PRIVATE_KEY=0x… DISABLE_BGP_CHECKS=1 npm run start   # ws://localhost:8001/ws
```

- `PRIVATE_KEY` is the witness's ETH key on secp256k1. Keep it on the witness
  host. Obtain its public address as described above and configure the attestor
  with `witnessAddress`.
- `AUTHENTICATION_PUBLIC_KEY`, the matching compressed secp256k1 public key,
  enables host-whitelisted auth requests; pass a matching `authRequest` to the
  prover. The signing key stays server-side. In a browser, fetch a pre-signed
  request from your own backend.
- Locally the endpoint is plain `ws://`; TLS termination (`wss://`) is a
  reverse-proxy concern in production.

For two witnesses at once, `packages/zk-tls/scripts/start-witnesses.sh` clones a
pinned `attestor-core` and starts sidecars on two ports. It is what the live
check uses; see the package README's "Live check".

## Witness agreement and upgrades

Every operator in one trusted set must run the same witness version and behavior.
Witnesses agree only when they add identical context fields to the Reclaim claim
identifier for the same request and disclosures. Thoth does not pin witness
behavior. An upstream change can silently split every affected trusted set;
the client fails closed with `witnesses disagree`, causing an availability failure.

Before rotating a trusted set after any witness version or behavior change,
run the [live check](../README.md#live-check) against the candidate witnesses.
Use `WITNESS_URLS` to name them and verify that they derive the same identifier
and message. Coordinate the change across all operators and rotate the set only
after the check passes.
