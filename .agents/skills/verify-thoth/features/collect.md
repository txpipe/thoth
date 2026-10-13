# A dApp collecting an attestment

A dApp pins its attestors in a `@thoth/client` trusted set, each at the registry slot its
contract gave the attestor's key, and collects an N-of-M attestment with
`@thoth/zk-tls/client`'s `zkFetchClient`: one fetch per attestor through that attestor's
prover, then the claim every witness agrees on, signed by the threshold, each signature vetted
and placed at its member's slot. `collect` does it in one call under a caller-fixed window;
`proveReq` then `attest` does it in two, with the window spanning the observations.

## Sub-features

- `collect-threshold` `collect` returns a claim, its 17-field message and one verified attestation per slot, sorted by registry slot.
- `collect-prove-attest` `proveReq` + `attest` collects the same, with the window derived from the observations.
- `collect-forged` a reply whose signature does not verify fails vetting.
- `collect-origin` evidence for another origin than the request is refused before any attestor is asked.
- `collect-options` an expired deadline and a threshold above the candidates are refused.
- `trusted-set` `buildTrustedSet` refuses two members at one slot and a slot outside the registry.

## How to get to it (user POV)

- `zkFetchClient.init({ trusted, transport, verifier, policy, appId, valueSlots, provers })`,
  then `client.collect(request, options)`.
- `client.proveReq(request, holder)`, then `proof.attest(...ids)`.
- `buildTrustedSet({ registrySize, attestors })` from `@thoth/client`.

## Driving it with control-thoth

Preconditions:

- The baseline: launched, doctor passes.
- `E=.evidence/$VERIFY_RUN_ID/collect`.
- The dApp: `operator-a` at slot `0` and `operator-b` at slot `2` of a 3-slot registry,
  `jubjubVerifier`, the drives' policy, app id `0xa1…a1`, `valueSlots` `3`; each prover
  replays the recorded evidence for `GET https://api.github.com/repos/reclaimprotocol/attestor-core`.
  `collect`'s options: the drives' holder, window `1786122944` to `1786123004`, threshold
  `2`, a deadline a minute out, `attestorTimeoutMs` `5000`.

- **Collect.** Run `$C run --evidence "$E/01-collect" --offline -- node "$D/collect.mjs" collect`.
  Exit `0`; `slots` `[0, 2]`, `messageLength` `17`, `sameMessage` `true`,
  `signaturesVerify` `[true, true]`, `failures` `[]`; `claim.windowStart` `"1786122944"`,
  `claim.windowEnd` `"1786123004"`, `claim.policyHash`
  `0x8da8bf6a39d629bdd7a669515223ec5c8d32e08b0523e78895dfa44083058321`.
- **Prove, then attest.** Run `$C run --evidence "$E/02-prove-attest" --offline -- node "$D/collect.mjs" prove-attest`.
  Exit `0`; `slots` `[0, 2]`, `sameMessage` `true`, `signaturesVerify` `[true, true]`;
  `claim.windowStart` and `claim.windowEnd` both `"1786122944"`, the one observation.
- **A forged reply, collecting.** Run `$C run --evidence "$E/03-forged-collect" --offline -- node "$D/collect.mjs" forged-collect`.
  Exit `1`, `error` `ZkFetchThresholdError`, `reason` `threshold`, `failures`
  `[{ "registryIndex": 2, "reason": "attestation" }]`.
- **A forged reply, attesting.** Run `$C run --evidence "$E/04-forged-attest" --offline -- node "$D/collect.mjs" forged-attest`.
  Exit `1`, `error` `AttestationMismatchError`, `reason` `signature`, `message`
  `attestation from "operator-b" failed signature check`.
- **Evidence for another origin.** Run `$C run --evidence "$E/05-other-origin" --offline -- node "$D/collect.mjs" other-origin`.
  Exit `1`, `message` `prover returned evidence for https://api.github.com, not the requested https://example.com`.
- **Expired deadline.** Run `$C run --evidence "$E/06-expired" --offline -- node "$D/collect.mjs" expired`.
  Exit `1`, `error` `ZkFetchThresholdError`, `reason` `expired`, `failures` `[]`.
- **Threshold above the set.** Run `$C run --evidence "$E/07-threshold-too-high" --offline -- node "$D/collect.mjs" threshold-too-high`.
  Exit `1`, `error` `ZkFetchThresholdError`, `reason` `invalid-options`.
- **Two members at one slot.** Run `$C run --evidence "$E/08-duplicate-slot" --offline -- node "$D/collect.mjs" duplicate-slot`.
  Exit `1`, `error` `InvalidTrustedSetError`, `reason` `duplicate-slot`, `message`
  `invalid trusted set: attestor "operator-b" claims an already-taken registry slot`.
- **A slot outside the registry.** Run `$C run --evidence "$E/09-slot-outside-registry" --offline -- node "$D/collect.mjs" slot-outside-registry`.
  Exit `1`, `error` `InvalidTrustedSetError`, `reason` `registry-index`.

## Gotchas

- `slots` are the app's registry slots, not the order the attestors answered or were listed:
  `[0, 2]` with slot `1` unqueried is the placement the contract checks positionally.
- `collect` signs the caller's window; `proveReq` signs the span of the witnesses'
  observations. Both sign the same values; only the window differs.
- The threshold errors carry registry slots and step reasons only, never remote error text:
  a forged reply shows as `attestation`, not as the verifier's words.
- Both operators trust the one recorded witness; in production each trusts its own, which the
  drive cannot record offline.
