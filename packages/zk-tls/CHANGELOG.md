# @txpipe/thoth-zk-tls

## 0.1.0

### Minor Changes

- 4bca1e3: First release under the `@txpipe/thoth-*` names.
- 9b3c6d5: `zkFetchPolicySchema` refuses an empty redaction: one whose `regex`, `jsonPath` and `xPath` are all absent or empty. Reclaim's attestor-core refused such a redaction on every prove, so a policy that has one now fails when the client starts.
- 9516b0f: `proveReq` no longer passes on the text of a prover's error. It rethrows a `ZkFetchProverError` with the same reason and no cause, or an `Error` that names only the attestor whose prover failed.
- a92a95d: A custom prover now gets its own copy of `publicHeaders`, `responseMatches` and `responseRedactions`, so it cannot change your policy or your headers for later proves.
- 2b32b84: `zod` is now a peer dependency (`^4.6.7`): install it in your app, and your schemas and the package share one copy. Every entry point also resolves from `require()`, and the package ships its `src/` so go-to-definition reaches the source.

### Patch Changes

- Updated dependencies [4bca1e3]
- Updated dependencies [2b32b84]
  - @txpipe/thoth-core@0.1.0
  - @txpipe/thoth-attestor@0.1.0
  - @txpipe/thoth-client@0.1.0
