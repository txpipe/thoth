# Package entry points

A consumer installs `@thoth/core`, `@thoth/attestor`, `@thoth/client`, `@thoth/zk-tls` and
`@thoth/contracts` and imports the TypeScript packages by the subpaths their `exports` maps
name; each resolves to the package's built `dist/`. A file the map does not name is not
importable, and each package ships its `dist/` (or, for contracts, its Compact sources) and
nothing of its sources or tests.

## Sub-features

- `exports-resolve` each of the eleven subpaths resolves to its package's `dist/` and loads.
- `exports-names` each subpath exports the runtime names its README lists.
- `exports-private` a path outside a package's `exports` is refused.
- `exports-pack` what each of the five packages ships.

## How to get to it (user POV)

- `import { … } from '@thoth/<package>[/<subpath>]'` in an app or a kind package.
- `npm pack` (or publishing) each workspace.

## Driving it with control-thoth

Preconditions:

- The baseline: launched, doctor passes.
- `E=.evidence/$VERIFY_RUN_ID/exports`.

- **Resolve every entry point.** Run `$C run --evidence "$E/01-resolve" --offline -- node "$D/exports.mjs" resolve`.
  Exit `0`; eleven objects, each `resolved` under `packages/<name>/dist/`, with these
  `exports`: `@thoth/attestor` `buildAttestor`, `defineAttestor`, `descriptorOf`;
  `@thoth/client` `attestorIdsOf`, `attestorOf`, `buildTrustedSet`, `memberOf`,
  `resolveAttestation`; `@thoth/client/errors` `AttestationMismatchError`,
  `AttestorNotInTrustedSetError`, `InvalidTrustedSetError`; `@thoth/client/jubjub`
  `jubjubVerifier`; `@thoth/core` none (`[]`); `@thoth/core/claim` `CLAIM_VERSION`,
  `bytes32Schema`, `claimSchema`, `claimToMessage`; `@thoth/core/claim-context`
  `claimContextDigestOf`, `holderCommitmentOf`, `policyHashOf`, `subjectHashOf`;
  `@thoth/zk-tls` `ZK_FETCH_LAW`, `assertEvidenceMatchesPolicy`, `assertPolicySlotsInRange`,
  `claimRequestOf`, `claimUrl`, `deriveClaimFromEvidence`, `normalizePolicy`,
  `parseDisclosedValue`, `parsedEvidenceView`, `zkFetchClaimSchema`, `zkFetchEvidenceSchema`,
  `zkFetchPolicyHashOf`, `zkFetchPolicySchema`, `zkFetchSubjectHashOf`, `zkFetchSubjectOf`;
  `@thoth/zk-tls/attestor` `assertClaimMatchesDisclosures`, `assertClaimMatchesSubject`,
  `assertObservationInWindow`, `createZkFetchDefinition`, `verifyZkFetchProof`,
  `zkFetchAttestor`; `@thoth/zk-tls/client` `ZkFetchThresholdError`, `addressFromWitnessId`,
  `toCanonicalEvidence`, `zkFetchClient`; `@thoth/zk-tls/prover` `zkFetchProver`.
- **A path outside `exports`.** Run `$C run --evidence "$E/02-private" --offline -- node "$D/exports.mjs" private`.
  Exit `1`, `code` `ERR_PACKAGE_PATH_NOT_EXPORTED`, `message` starting
  `Package subpath './dist/claim.js' is not defined by "exports"`.
- **What each package ships.** Run `$C run --evidence "$E/03-pack" --offline -- npm pack --dry-run --json --workspaces`.
  Exit `0`; stdout is a JSON array of five packages. The `files` of `@thoth/attestor`,
  `@thoth/client`, `@thoth/core` and `@thoth/zk-tls` are `README.md`, `package.json` and
  files under `dist/` only; `@thoth/contracts`'s are `README.md`, `package.json`,
  `attestation.compact`, `attestor_registry.compact` and `examples/example_app.compact`. No
  `src/` or `test/` path appears.

## Gotchas

- `@thoth/core`'s root entry is types only (`AttestorDefinition`, `Attestation`, …): its
  runtime exports are `[]`, and `import type` is how a consumer uses it.
- A stale `dist/` answers with the old names: doctor fails on any source changed since the
  build; relaunch rather than trusting the list.
- The list of subpaths comes from each workspace's `package.json` `exports`; a new subpath is
  driven without editing the script, but its expected names belong in this file.
- `npm pack` writes `npm notice` lines to stderr; the JSON is stdout only.
