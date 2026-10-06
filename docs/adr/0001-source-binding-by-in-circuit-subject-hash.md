# Source binding by in-circuit subject hash

Status: accepted

A claim carries `subjectHash`, a hash of what the attestation is about. To make an app accept only a specific source, the app supplies the subject fields as a private witness, and the circuit recomputes the hash and compares it to `claim.subjectHash`, disclosing only the fields its policy needs. So the hash must be a circuit hash (`persistentHash`, or `transientHash` when the hash is never disclosed or stored), not SHA-256, because the circuit cannot recompute SHA-256. This enforces source binding on-chain while keeping private parts of the subject, such as an account id, hidden. It closes the source-binding finding (#72).
