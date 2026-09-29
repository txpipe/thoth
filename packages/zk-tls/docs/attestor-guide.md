# Deploying a zkFetch attestor

The host side of the zkFetch kind: build an attestor instance, give it the
witness key and the policy it enforces.
See the [package README](../README.md) for what the package exports and
[dapp-integration.md](dapp-integration.md) for the dApp side.

## Building an instance

An attestor instance is a `KeyPair`, a placement in the on-chain registry, and
the key of the Reclaim witness the operator runs. The key pair comes from the
signature scheme's key package and is held by `@thoth/attestor`'s
`AttestorSigner`; nothing in this package touches a private key.

```ts
import { zkFetchAttestor } from '@thoth/zk-tls/attestor';

const attestor = zkFetchAttestor({
  id: 'zkFetch-strava-1',
  keyPair, // the attestor's signing key, not the witness's
  registryIndex: 0,
  witnessKey: '0x…the secp256k1 key of your Reclaim witness…',
});
```

`registryIndex` is the slot of this attestor's public key in the registry's
pinned key vector. The contract verifies signatures positionally, so the index
must match the deployment's registry slot.

`witnessKey` is the private key the operator's own Reclaim witness signs with.
The instance derives its address once, at build time, and rejects any evidence
signed by a different witness.

## The attest flow

The dApp sends the raw input over the transport; the attestor parses it with
its own schemas and runs the full check before signing:

1. `verifyZkFetchProof(evidence)` re-verifies the Reclaim witness's ECDSA
   signature over the claim, checks the claim identifier against its signed
   content, and extracts the values it disclosed.
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
witness is not the instance's own `witnessKey`. Only then does it sign the
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

- `PRIVATE_KEY` is an ETH key on secp256k1. Give this key to the attestor as
  `witnessKey`, so the attestor accepts only this witness's evidence. Read the
  address off the key with any ETH tooling, for example
  `cast wallet address --private-key …`.
- `AUTHENTICATION_PUBLIC_KEY`, the matching compressed secp256k1 public key,
  enables host-whitelisted auth requests; pass a matching `authRequest` to the
  prover. The signing key stays server-side. In a browser, fetch a pre-signed
  request from your own backend.
- Locally the endpoint is plain `ws://`; TLS termination (`wss://`) is a
  reverse-proxy concern in production.

For two witnesses at once, `packages/zk-tls/scripts/start-witnesses.sh` clones a
pinned `attestor-core` and starts sidecars on two ports. It is what the live
check uses; see the package README's "Live check".
