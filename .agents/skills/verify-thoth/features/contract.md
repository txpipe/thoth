# The contract accepting an attestment

An app embeds `attestation` and `attestor_registry` from `@thoth/contracts` in its own
Compact contract, as `packages/contracts/examples/example_app.compact` does (2-of-3, three
value slots), and compiles it with the pinned compiler. Deployed, it seals the registry keys,
the accepted policy hashes, the freshness window and the maximum window; `verifyAttestation`
takes a claim and its signatures as private witness data and, when every check passes, records
the observation's nullifier and vaults the claim under its commitment.

## Sub-features

- `contract-compile` the example app compiles with `compact compile +0.34.0 --skip-zk`.
- `contract-deploy` the deployed ledger holds the sealed windows and policy hash, and no claim.
- `contract-accept` a 2-of-3 attestment the dApp collected is accepted: one nullifier, one vault entry with the claim's window.
- `contract-replay` the same observation again is refused, whatever the vault randomness.
- `contract-signatures` one valid signature, or valid signatures at the wrong slots, are refused.
- `contract-policy` a claim under a policy the app did not seal is refused.
- `contract-holder` a caller without the holder's secret is refused.
- `contract-window` a window longer than the app's maximum, a submission after the freshness window, and one before the window opens are refused.

## How to get to it (user POV)

- `compact compile +0.34.0 [--skip-zk] <app>.compact <out>` on a contract importing the modules.
- Deploy the compiled `Contract` with its witnesses (`seedKeys`, `seedPolicies`,
  `getAttestationWitness`, `getHolderSecret`) and call its `verifyAttestation` circuit.

## Driving it with control-thoth

Preconditions:

- The baseline: launched, doctor passes; `. "$($C env)"` for `$RUN_DIR`.
- `E=.evidence/$VERIFY_RUN_ID/contract`.
- Every step but `compile` deploys a fresh example app with the dApp's registry keys
  (`operator-a`, an unqueried operator, `operator-b`) and the drives' policy hash, collects an
  attestment as [collect.md](./collect.md)'s `collect` does, places its signatures by slot (the
  unqueried slot gets a signature that never verifies), and submits it at block time
  `1786123004`, the window's end, unless the step says otherwise.

- **Compile.** Run `$C run --evidence "$E/01-compile" --offline -- compact compile +0.34.0 --skip-zk packages/contracts/examples/example_app.compact "$RUN_DIR/example_app"`
  and `$C run --evidence "$E/02-outputs" --offline -- ls "$RUN_DIR/example_app" "$RUN_DIR/example_app/contract" "$RUN_DIR/example_app/zkir"`.
  Exit `0` each; the outputs are `compiler`, `contract` (`index.d.ts`, `index.js`,
  `index.js.map`) and `zkir` (`verifyAttestation.zkir`), and no `keys`.
- **Deploy.** Run `$C run --evidence "$E/03-deploy" --offline -- node "$D/contract.mjs" deploy`.
  Exit `0`; `freshnessWindow` `"3600"`, `maxWindow` `"300"`, `policyHashes`
  `["0x8da8bf6a39d629bdd7a669515223ec5c8d32e08b0523e78895dfa44083058321"]`, `nullifiers`
  `"0"`, `claimsVault` `[]`.
- **Accept.** Run `$C run --evidence "$E/04-accept" --offline -- node "$D/contract.mjs" accept`.
  Exit `0`; `nullifiers` `"1"`; `claimsVault` one entry with `holder`
  `"12640092001967751544650359551639796700446478361679952809521553481833506285847"`,
  `windowStart` `"1786122944"`, `windowEnd` `"1786123004"` (its `id` differs per run).
- **Replay.** Run `$C run --evidence "$E/05-replay" --offline -- node "$D/contract.mjs" replay`.
  Exit `1`, `error` `CompactError`, `message` `failed assert: Observation replay`.
- **One signature.** Run `$C run --evidence "$E/06-one-signature" --offline -- node "$D/contract.mjs" one-signature`.
  Exit `1`, `message` `failed assert: Insufficient valid signatures`.
- **Signatures at the wrong slots.** Run `$C run --evidence "$E/07-swapped-slots" --offline -- node "$D/contract.mjs" swapped-slots`.
  Exit `1`, `message` `failed assert: Insufficient valid signatures`.
- **Unsealed policy.** Run `$C run --evidence "$E/08-unaccepted-policy" --offline -- node "$D/contract.mjs" unaccepted-policy`.
  Exit `1`, `message` `failed assert: Unaccepted policy`.
- **Wrong holder secret.** Run `$C run --evidence "$E/09-holder-mismatch" --offline -- node "$D/contract.mjs" holder-mismatch`.
  Exit `1`, `message` `failed assert: Holder mismatch`.
- **Window too long.** The attestors sign a 301-second window. Run `$C run --evidence "$E/10-window-too-long" --offline -- node "$D/contract.mjs" window-too-long`.
  Exit `1`, `message` `failed assert: Window too long`.
- **Too old.** Submitted at the window's end plus `3600`. Run `$C run --evidence "$E/11-too-old" --offline -- node "$D/contract.mjs" too-old`.
  Exit `1`, `message` `failed assert: Window too old`.
- **In the future.** Submitted a second before the window opens. Run `$C run --evidence "$E/12-in-the-future" --offline -- node "$D/contract.mjs" in-the-future`.
  Exit `1`, `message` `failed assert: Window in the future`.

## Gotchas

- `replay` submits the accepted attestment, then the same one under fresh vault randomness:
  its exit `1` is the second call's refusal, after the first was accepted.
- The vault entry's `holder` is the vault pseudonym the contract derives from the secret, a
  field element, not the claim's `holder` commitment.
- A refused call leaves the simulated ledger as it was; the drive prints the refusal, not a
  ledger, so a refusal's proof is its assert text.
- `--skip-zk` skips the proving keys, not the circuits: `verifyAttestation` runs in full on
  the simulator. Compiling with keys is not driven (README, "Not mapped by default").
- After a change to a `.compact` file, the run's compiled app is stale: doctor fails until you
  `cleanup` and `launch` again.
