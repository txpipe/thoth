# No kind on-chain; the policy is the commitment

Status: accepted

The signed claim carries no kind code. `policyHash`, a hash of the policy the attestors enforced, is the on-chain binding: the contract seals the hash it accepts and asserts equality. A kind code is redundant with the pinned attestor keys and unenforceable by the circuit, while the policy hash is something the contract can compare and a requester cannot forge. The kind stays an off-chain concept (the attestor's law). A second kind is a new policy with its own hash, served by the same contract module. This costs on-chain kind distinguishability, so mixed-kind thresholds and multi-policy contracts need a set of accepted hashes instead of one.
