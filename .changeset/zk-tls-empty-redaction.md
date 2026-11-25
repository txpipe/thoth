---
'@txpipe/thoth-zk-tls': minor
---

`zkFetchPolicySchema` refuses an empty redaction: one whose `regex`, `jsonPath` and `xPath` are all absent or empty. Reclaim's attestor-core refused such a redaction on every prove, so a policy that has one now fails when the client starts.
