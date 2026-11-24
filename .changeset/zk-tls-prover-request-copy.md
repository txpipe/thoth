---
'@txpipe/thoth-zk-tls': minor
---

A custom prover now gets its own copy of `publicHeaders`, `responseMatches` and `responseRedactions`, so it cannot change your policy or your headers for later proves.
