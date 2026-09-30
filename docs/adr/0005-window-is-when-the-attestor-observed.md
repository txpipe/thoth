# The window is when the attestor observed

Status: accepted

The claim's observation window is when the attestor looked, not when the underlying fact happened. The contract checks the window against its own clock, Midnight time, so it bounds how late a claim can be submitted and stays identical for every kind. When the fact happened, for example an event's block number or timestamp, travels as a claim value. The attestor's law checks that value for recency and finality against the source chain, because only the attestor can see that chain, and the app predicate can apply its own bound to the same value. A kind therefore never asks the contract to understand source-chain time, and a window never carries the fact's time.
