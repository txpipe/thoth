---
'@txpipe/thoth-zk-tls': minor
---

`proveReq` no longer passes on the text of a prover's error. It rethrows a `ZkFetchProverError` with the same reason and no cause, or an `Error` that names only the attestor whose prover failed.
