# The window is when the attestor observed

Status: accepted

The claim's observation window is when the attestor looked, not when the underlying fact happened. The contract checks the window against its own clock, Midnight block time, so it bounds how late a claim can be submitted and stays identical for every kind. When the fact happened, for example an event's block number or timestamp, travels as a claim value. The attestor's law checks that value for recency and finality against the source chain, because only the attestor can see that chain, and the app predicate can apply its own bound to the same value. A kind therefore never asks the contract to understand source-chain time, and a window never carries the fact's time.

The window is also not the exact observation time. A zkFetch witness takes its observation time (`timestampS`) from the request, and Reclaim rejects it only if it is more than 10 minutes in the future, with no lower bound. So the window shows the fetch happened no earlier than about 10 minutes before `windowStart`. Freshness still holds on-chain, because post-dating is capped (#67). Apps must not read the window as the time of the fact.
