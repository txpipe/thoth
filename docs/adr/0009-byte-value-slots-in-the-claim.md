# The claim carries byte value slots

Status: accepted

The claim carries `W` fixed-width byte value slots (`Bytes<32>`) alongside its `V` numeric `Uint<64>` slots, addressed by one `present` mask of length `V+W`: numeric slots first, byte slots after. A byte value is exactly its 32 bytes; no length travels in the claim, and a policy's parse rule canonicalizes a source's string into the slot, zero-padding shorter values. A hash was rejected: it is lossy, and with no SHA-256 in the pinned stdlib a circuit could never recompute it from the source. In the signed message each byte value degrades to two adjacent fields, bytes 0-15 then bytes 16-31 as `Uint<128>`; `W = 0` reproduces the numeric-only layout exactly.

Wire-order note (implemented): the signed message carries one presence flag per 16-byte half (`B = 2W` flags, `bytePresent`) rather than one per byte value, because a `W = 0` specialization must still compile and zero-length vectors cannot be indexed. The field count is therefore `K = 11 + 2V + 2B` (equivalently `11 + 2V + 4W`), and each byte value's two fields stay adjacent.

Canonicalization note: the string→slot mapping is not injective — trailing NUL bytes collapse into the zero padding and unpaired surrogates normalize to U+FFFD — so a byte slot's identity is the padded 32 bytes, not the source string. Fixed width is what lets a circuit compare values without a length, and a hash was already rejected as lossy.

Privacy note: the replay nullifier (ADR 0006) is a public, unsalted hash of the observation, and every other input to it is public or guessable — the transaction discloses the policy hash and the window, the app id is the app's constant, and a fixed endpoint fixes the subject hash. Anyone can therefore confirm a guessed byte value by recomputing the nullifier. Numeric values were always exposed this way, but byte slots carry identifiers, which are easy to enumerate. ADR 0006 rules out client randomness in the nullifier, so this is accepted: an app whose byte values must stay secret should not rely on the claim keeping them hidden.
