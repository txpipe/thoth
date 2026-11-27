# @txpipe/thoth-contracts

## 0.1.0

### Minor Changes

- 4bca1e3: First release under the `@txpipe/thoth-*` names.

### Patch Changes

- d600820: `verifyAttestation` no longer asserts `Claim already accepted`. The assert could never fire: an equal vault id commits to the same claim, and the replay check has already rejected that claim's nullifier with `Observation replay`.
