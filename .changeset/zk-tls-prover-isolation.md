---
'@txpipe/thoth-zk-tls': minor
---

`proveReq` no longer passes on the text of a prover's error. It rethrows a `ZkFetchProverError` with the same reason and no cause, or an `Error` that names only the attestor whose prover failed. A custom prover now gets its own copy of `publicHeaders`, `responseMatches` and `responseRedactions`, so it cannot change your policy. `zkFetchPolicySchema` refuses a redaction with no non-empty `regex`, `jsonPath` or `xPath`; Reclaim's attestor-core refused such a redaction on every prove.
