# The nullifier hashes a secret salt the attestors derive from the evidence

Status: accepted; for chain-event kinds, amended by [ADR 0014](0014-chain-event-kinds.md): the salt is public, because the values are public chain data. Also amended by [ADR 0015](0015-attestors-sign-the-nullifier.md): the signed message no longer carries the salt's halves. The salt reaches it through the nullifier, and the message is seven fields.

The nullifier (ADR 0006) was a public hash of fields that are all public or guessable except the values, so anyone could confirm a guessed value by recomputing it and looking it up in the ledger (issue #155). Identifiers, country codes, ages and small balances are easy to enumerate. The claim now carries a signed 32-byte `salt`, the contract hashes it into the observation identity, and the salt never appears on-chain, so the public fields no longer determine the nullifier.

The kind's law derives the salt from the evidence, and the attestor refuses a claim proposal whose salt differs. The kind fixes the salt from the evidence, so the client cannot change it without new evidence: ADR 0006 rules out client randomness because a client could vary it to mint several claims for one fact. zkFetch takes the salt from the claim context digest every witness signs into its context. That digest commits to the holder commitment, which never appears on-chain, so it is secret to outsiders, and every attestor given the same claim context derives the same salt. It follows the holder and window the client binds before proving (ADR 0011), so the client does pick it, through the holder, before any witness signs. The digest is the client's claim context, not a commitment to the evidence, so ADR 0007 stands.

Considered options: an app-held secret (every app would have to manage one, and a leak of it reopens every past nullifier); a per-app note that values must be hard to guess (leaves the core promise false for most identifiers); client randomness (ruled out by ADR 0006).

Consequences:

- The wire layout grows by two fields: `K = 14 + 2V + 2B`, with the salt's two halves right after the holder's.
- Whoever holds the evidence can recompute the salt. They already know the values, so this reveals nothing new.
- In zkFetch the salt follows the holder, so the nullifier no longer stops one fact from being claimed again under a fresh holder, even in the same window. ADR 0011 fixes the window before the fetch, so without the salt a new fetch in the same window with the same values collided with the earlier nullifier; with it, a fresh holder gets a fresh salt and a fresh nullifier. The evidence binding (ADR 0011) stops only the reuse of evidence signed for another holder. An app that needs one claim per fact keeps its own set keyed on that fact, which confirms guesses at whatever it keys on.
- While the salt follows the holder, neither fix direction in #112 (drop the window from the observation identity, or pin it to the witness's observation) bounds how many claims one fact mints. #172 decides the window's role together with the salt's source: a salt the client cannot steer and that stays the same across fetches of one fact, such as a keyed PRF the attestors share, would close both.
- A kind whose salt the client can change without new evidence breaks replay protection: one observation would mint many claims.

Amends ADR 0006 (the observation identity includes the salt) and supersedes the privacy note in ADR 0009.
