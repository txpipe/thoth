# Deploying a zkFetch attestor

The host side of the zkFetch kind: build an attestor instance, give it the
policy it enforces.
See the [package README](../README.md) for what the package exports and
[dapp-integration.md](dapp-integration.md) for the dApp side.

## Building an instance

An attestor instance is a `KeyPair` plus a placement in the on-chain registry.
The key pair comes from the signature scheme's key package and is held by
`@thoth/attestor`'s `AttestorSigner`; nothing in this package touches a private
key.

```ts
import { zkFetchAttestor } from '@thoth/zk-tls/attestor';

const attestor = zkFetchAttestor({
  id: 'zkFetch-strava-1',
  keyPair,
  registryIndex: 0,
});
```

`registryIndex` is the slot of this attestor's public key in the registry's
pinned key vector. The contract verifies signatures positionally, so the index
must match the deployment's registry slot.

## The attest flow

The dApp sends the raw input over the transport; the attestor parses it with
its own schemas and runs the full check before signing:

1. `verifyZkFetchProof(evidence)` re-verifies the Reclaim witness's ECDSA
   signature over the claim and extracts the values it disclosed.
2. `assertEvidenceMatchesPolicy(verified, policy)` checks the attested URL
   against the host allowlist, the signing witness against
   `attestorAddresses`, every required slot's certifiability, and any size
   bound.
3. `assertClaimMatchesDisclosures({ claim, disclosures, policy })` enforces
   that the client-proposed claim says exactly what the evidence disclosed.

`attestor.attest({ policy, evidence, claim })` runs these three steps. It
rejects the input if the evidence is not canonical, if it does not match the
policy, or if the proposed claim disagrees with the disclosures. Only then
does it sign the attestor-derived claim: values and present bits from the
disclosed values, a deterministic nonce, and a claim bound to the evidence by
its hash.

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

- `PRIVATE_KEY` is an ETH key on secp256k1. Its address is what policies pin
  in `attestorAddresses`. To read it off a key you run yourself, use any ETH
  tooling (for example `cast wallet address --private-key …`), or run
  `packages/zk-tls/scripts/make-fixture.mjs` once, which prints the witness
  address to the console.
- `AUTHENTICATION_PUBLIC_KEY`, the matching compressed secp256k1 public key,
  enables host-whitelisted auth requests; pass a matching `authRequest` to the
  prover. The signing key stays server-side. In a browser, fetch a pre-signed
  request from your own backend.
- Locally the endpoint is plain `ws://`; TLS termination (`wss://`) is a
  reverse-proxy concern in production.
