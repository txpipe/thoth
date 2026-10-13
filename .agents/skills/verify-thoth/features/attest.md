# An operator's zkFetch attestor

An attestor operator runs `zkFetchAttestor({ id, keyPair, witnessAddress })` from
`@thoth/zk-tls/attestor`. Given a policy, a client's witness evidence and the claim the client
proposes, it verifies the witness's signature, checks the evidence against the policy, the
proposed window and the proposed claim, and signs the claim it derives itself with its Jubjub
key; anything else it refuses. `verifyZkFetchProof` is the verification on its own.

## Sub-features

- `attest-verify` the recorded witness evidence verifies offline and names what it disclosed.
- `attest-sign` an honest proposal is signed: the claim carries the policy's hash and the request's subject hash, and the signature verifies under the operator's key.
- `attest-tampered` evidence whose signature or signed request was altered is refused.
- `attest-witness` evidence from a witness other than the operator's is refused.
- `attest-policy` evidence for a host outside the policy, or missing a required slot, is refused.
- `attest-window` a proposed window that does not hold the witness's observation is refused.
- `attest-overclaim` a proposal claiming a value the evidence did not disclose is refused.

## How to get to it (user POV)

- An operator's service calls `attestor.attest({ policy, evidence, claim })` for each request
  a dApp's transport forwards.
- `verifyZkFetchProof(evidence)` to check a witness proof alone.

## Driving it with control-thoth

Preconditions:

- The baseline: launched, doctor passes.
- `E=.evidence/$VERIFY_RUN_ID/attest`.
- Every step but `other-witness` uses operator `operator-a`, trusting the recorded witness
  `0xc340fc267cacbb9e3101adced0c7728f7e63b63d`, the drives' policy, and a proposal derived
  from the evidence over the window `1786122944` to `1786123004`.

- **Verify the evidence.** Run `$C run --evidence "$E/01-verify" --offline -- node "$D/attest.mjs" verify`.
  Exit `0`; `witness` `0xc340fc267cacbb9e3101adced0c7728f7e63b63d`, `identifier`
  `0x1a36ab63aef0496c591235b96b84bac1553ac08752fa8f38e7d088c912c38bb9`, `observedAt`
  `1786122944`, `disclosed` `["data"]`.
- **Sign.** Run `$C run --evidence "$E/02-sign" --offline -- node "$D/attest.mjs" sign`.
  Exit `0`; `claim.policyHash`
  `0x8da8bf6a39d629bdd7a669515223ec5c8d32e08b0523e78895dfa44083058321`, `claim.subjectHash`
  `0x922af07fbce42dd046e5ecaceb86e509e57663b31935ebbeb9a5c3b996e86b19`, `windowStart`
  `"1786122944"`, `windowEnd` `"1786123004"`, `present` `[false, false, false]`, `values`
  `["0", "0", "0"]`; `messageLength` `17`; `policyHashIsThePolicys`,
  `subjectHashIsTheRequests` and `signatureVerifies` all `true`.
- **Tampered signature.** Run `$C run --evidence "$E/03-tampered-signature" --offline -- node "$D/attest.mjs" tampered-signature`.
  Exit `1`, `message` `Invalid claim signature`.
- **Tampered request.** Run `$C run --evidence "$E/04-tampered-request" --offline -- node "$D/attest.mjs" tampered-request`.
  Exit `1`, `message` `Invalid claim signature`.
- **Another witness.** Run `$C run --evidence "$E/05-other-witness" --offline -- node "$D/attest.mjs" other-witness`.
  Exit `1`, `message` `evidence signed by witness 0xc340fc267cacbb9e3101adced0c7728f7e63b63d, not this attestor's witness 0x1111111111111111111111111111111111111111`.
- **Host outside the policy.** Run `$C run --evidence "$E/06-host-not-allowed" --offline -- node "$D/attest.mjs" host-not-allowed`.
  Exit `1`, `message` `attested host api.github.com not in allowlist [example.com]`.
- **Required slot not certifiable.** Run `$C run --evidence "$E/07-required-slot" --offline -- node "$D/attest.mjs" required-slot`.
  Exit `1`, `message` `policy requires a certifiable value for "data" but the proof did not disclose a parseable value`.
- **Window misses the observation.** Run `$C run --evidence "$E/08-window-misses" --offline -- node "$D/attest.mjs" window-misses`.
  Exit `1`, `message` `witness observation 1786122944 is outside the claim window [1786122945, 1786123005]`.
- **Overclaim.** Run `$C run --evidence "$E/09-overclaim" --offline -- node "$D/attest.mjs" overclaim`.
  Exit `1`, `message` `claim slot 0 does not match the disclosed value for "data"`.

## Gotchas

- The recorded evidence discloses the whole HTTP response as `data`, which `float` cannot
  parse, so the honest claim has no slot present. That is the kind's law (an unparseable
  optional slot is signed unpresent), not a failed drive.
- A refusal's `error` is `Error` for every check here; tell them apart by `message`.
- The operator's key is fresh each run: compare `signatureVerifies`, not signature bytes.
