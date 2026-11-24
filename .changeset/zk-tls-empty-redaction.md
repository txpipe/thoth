---
'@txpipe/thoth-zk-tls': minor
---

`zkFetchPolicySchema` refuses a redaction with no non-empty `regex`, `jsonPath` or `xPath`. Reclaim's attestor-core refused such a redaction on every prove, so a policy that has one now fails when the client starts.
