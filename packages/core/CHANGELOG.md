# @txpipe/thoth-core

## 0.1.0

### Minor Changes

- 4bca1e3: First release under the `@txpipe/thoth-*` names.
- 2b32b84: `zod` is now a peer dependency (`^4.6.7`): install it in your app, and your schemas and the package share one copy. Every entry point also resolves from `require()`, and the package ships its `src/` so go-to-definition reaches the source.
