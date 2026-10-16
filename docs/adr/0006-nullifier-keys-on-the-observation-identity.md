# The nullifier keys on the observation identity, not a client nonce

Status: accepted

The claim carries no nonce. The contract derives the nullifier from the observation identity the attestors signed: the app id, `policyHash`, `subjectHash`, window, the numeric and byte values, and `present`. It excludes `holder`, so a fresh holder secret cannot be used to re-claim the same fact. No client-chosen randomness, because a client could vary it to mint several claims for one fact. Uniqueness follows from the agreed fields: a fetch is unique by its response and observation time, an event by its identity. The app id is part of the identity, so a claim cannot be replayed into a different app.
