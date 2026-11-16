# Evidence binds the claim context

Status: accepted; for chain-event kinds, amended by [ADR 0014](0014-chain-event-kinds.md): the evidence is a locator the attestor re-reads, so no witness binds the claim context.

The attestor takes the holder and window from the claim proposal, so on their own they bind nothing: whoever saw zkFetch evidence could have the attestors sign its observation under their own holder (#134). We bind them to the evidence. A kind has its witness sign `claimContextDigestOf` of the [claim context](../../CONTEXT.md#the-claim) (policy hash, subject hash, holder, window) with the evidence, and the attestor recomputes the digest from the policy, the signed request and the proposal, and refuses evidence that does not carry it. In zkFetch the client puts the digest in every witness's request context under `thothClaimContext`, the witness signs it with the evidence, and the attestor checks it in `assertClaimMatchesContext`.

## Consequences

- The holder and window are fixed before any witness signs. `proveReq` takes them up front, like `collect`, instead of spanning the window over the witnesses' observation times.
- `thothClaimContext` is reserved in a zkFetch request's `context`; a request that sets it is refused.
- The claim still does not commit to the evidence (ADR 0007): the binding runs from the evidence to the claim, checked by the attestor, not from the claim to the evidence.
