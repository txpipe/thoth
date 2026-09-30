# Colluding attestors are out of scope

Status: accepted

If N or more attestors in an app's trusted set collude, they can sign a claim under a policy they do not actually enforce, and nothing on-chain can stop it. The design accepts this for the MVP: the threshold assumes the pinned operators are honest and independent. The consequence is that `policyHash` and `subjectHash` defend against a malicious requester, not against a malicious attestor, and the contract's checks are only as strong as the honesty of the keys the app pinned.
