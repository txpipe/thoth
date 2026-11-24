---
'@txpipe/thoth-core': minor
'@txpipe/thoth-attestor': minor
'@txpipe/thoth-client': minor
'@txpipe/thoth-zk-tls': minor
'@txpipe/thoth-cardano': minor
---

`zod` is now a peer dependency (`^4.6.7`): install it in your app, and your schemas and the package share one copy. Every entry point also resolves from `require()`, and the package ships its `src/` so go-to-definition reaches the source.
