---
'@txpipe/thoth-zk-tls': minor
'@txpipe/thoth-cardano': minor
---

The attestors sign the seven-field message of `@txpipe/thoth-contracts`: the claim's version, its layout, its nullifier and its holder. Their signatures verify only against a contract built from the matching `@txpipe/thoth-contracts` release.
