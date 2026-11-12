# The contract seals its app id

Status: accepted

ADR 0006 said the app id in the observation identity stops a claim from being replayed into a different app. It does not: each contract keeps its own nullifier set, so the app id only separates nullifiers within one contract (issue #176). A client chooses the app id freely, and a second app that pins the same attestor keys and accepts the same policy hash would store a claim already stored by the first, so one fact counted once per app.

The attestation module now seals one app id, set by the top-level constructor like the policy hashes, and `verifyAttestation` rejects a claim whose `appId` differs (`"App id mismatch"`). The binding holds in-circuit, so an app does not have to remember to compare `appId` in its own predicate.

Considered options: leave the check to each app's predicate (the example app and the README's sample skipped it, so every app copied the gap); a set of app ids like the policy hashes (no use case: an app that wants another app's claims can seal that app's id).

Consequences:

- A deploy passes the app id to the constructor. A contract deployed for one app id never accepts a claim for another; to change it, deploy a new contract.
- Within one contract every accepted claim carries the same app id, so the app id no longer separates nullifiers there. It stays in the observation identity.

Amends ADR 0006: the sealed app id, not the nullifier, stops replay into another app.
