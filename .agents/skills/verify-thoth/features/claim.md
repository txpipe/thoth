# The claim and its message

A kind author and a dApp work with the canonical claim through `@thoth/core/claim`:
`claimSchema(V)` validates a raw claim and coerces its numbers to bigints, and
`claimToMessage` flattens it into the `K = 2*V + 11` fields attestors sign and the contract
rebuilds. The app's own compiled contract computes the same message in-circuit. The
claim-context hashes of `@thoth/core/claim-context` are stable functions of their inputs.

## Sub-features

- `claim-parse` a raw claim with plain numbers parses to the canonical claim, `version` defaulted to `1`.
- `claim-bytes32` a 32-byte field of another length is refused.
- `claim-presence` the schema accepts an absent slot carrying a value (the contract is what refuses it).
- `claim-message` the flat message has 17 fields for `V = 3`, in the wire order.
- `claim-parity` the off-chain message equals the compiled example app's `message` circuit field for field.
- `claim-hashes` `policyHashOf`, `subjectHashOf`, `holderCommitmentOf` and `claimContextDigestOf` give pinned values.

## How to get to it (user POV)

- `claimSchema(V).parse(raw)` and `claimToMessage(claim)` from `@thoth/core/claim`.
- `pureCircuits.message(claim)` from the app's compiled contract (the example app exports it).
- `policyHashOf`, `subjectHashOf`, `holderCommitmentOf`, `claimContextDigestOf` from
  `@thoth/core/claim-context`.

## Driving it with control-thoth

Preconditions:

- The baseline: launched, doctor passes (the example app is compiled in the run dir).
- `E=.evidence/$VERIFY_RUN_ID/claim`.

The raw claim the steps use: `appId` bytes `0x00…0x1f`, `policyHash` `0x20…0x3f`,
`subjectHash` `0x40…0x5f`, window `1786122944` to `1786123004`, holder `0x9acf97bb…c5a0`,
`present` `[true, true, false]`, `values` `[42, 0, 0]`, as plain numbers.

- **Parse.** Run `$C run --evidence "$E/01-parse" --offline -- node "$D/claim.mjs" parse`.
  Exit `0`; `version` `"1"`, `windowStart` `"1786122944"`, `windowEnd` `"1786123004"`,
  `values` `["42", "0", "0"]`, `present` `[true, true, false]`.
- **A short app id.** Run `$C run --evidence "$E/02-short-app-id" --offline -- node "$D/claim.mjs" short-app-id`.
  Exit `1`, `error` `ZodError`, `message` naming path `appId` and `expected 32 bytes`.
- **An absent slot with a value.** Run `$C run --evidence "$E/03-absent-nonzero" --offline -- node "$D/claim.mjs" absent-nonzero`.
  Exit `0`, `parsed` `true`, `present` `[true, false, false]`, `values` `["42", "7", "0"]`.
- **The message.** Run `$C run --evidence "$E/04-message" --offline -- node "$D/claim.mjs" message`.
  Exit `0`, `length` `17`; `message[0]` `"1"`; `[1]`, `[2]` `"20011376718272490338853433276725592320"`,
  `"41362427191743139026751447860679676176"` (the app id's bytes 0–15 and 16–31, each read
  little-endian); `[5]`, `[6]` `"1786122944"`, `"1786123004"`; `[9]`, `[10]`
  `"331104414588583303363818216021154058138"`, `"213704483592310324278099812323057061094"`
  (the holder); `[11..13]` `"1"`, `"1"`, `"0"`; `[14..16]` `"42"`, `"0"`, `"0"`.
- **Parity with the contract.** Run `$C run --evidence "$E/05-parity" --offline -- node "$D/claim.mjs" parity`.
  Exit `0`, `{ "offChainLength": 17, "inCircuitLength": 17, "differing": [] }`.
- **Claim-context hashes.** Run `$C run --evidence "$E/06-hashes" --offline -- node "$D/claim.mjs" hashes`.
  Exit `0`; `policyHash`
  `0x5c467852cce9b7342726b5f3b43e5d43d1c5291b69656ff0ea9d762dac16b7e4`, `subjectHash`
  `0xfdeab9acf3710362bd2658cdc9a29e8f9c757fcf9811603a8c447cd1d9151108`, `holder`
  `0x9acf97bbb544fa9b39f8bb70036418f9e6cc1d2bad398095c9b4cf0586fcc5a0`,
  `claimContextDigest`
  `0x9ba89671ae569a3a04e09a8eef82dde350b0de8eca5327fde76934e772fa9de1`. The same values on
  every run.

## Gotchas

- A changed hash value here is a changed canonical form, which changes every policy hash and
  holder an app has sealed or issued. It is either the change's intent (update this file in
  the same PR and say so) or a regression.
- `differing` lists the indices where the two messages disagree; an empty list with both
  lengths `17` is parity. A recompiled example app is needed after a `.compact` change:
  doctor fails until you relaunch.
- The schema does not check presence against values; `absent-nonzero` parsing is the current
  behaviour, and the contract's `Absent slot has nonzero value` is the guard.
