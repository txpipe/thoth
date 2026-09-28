# The contract accepts a set of policy hashes

Status: accepted

A contract seals a set of accepted policy hashes, not one, and accepts a claim whose `policyHash` is a member of the set. This lets one contract accept several policies, which is how it serves more than one attestor kind without a per-kind contract.
