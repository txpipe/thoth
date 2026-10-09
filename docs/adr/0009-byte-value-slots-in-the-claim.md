# The claim carries byte value slots

Status: accepted

The claim carries `W` fixed-width byte value slots (`Bytes<32>`) alongside its `V` numeric `Uint<64>` slots, addressed by one `present` mask of length `V+W`: numeric slots first, byte slots after. A byte value is exactly its 32 bytes; no length travels in the claim, and a policy's parse rule canonicalizes a source's string into the slot, zero-padding shorter values. A hash was rejected: it is lossy, and with no SHA-256 in the pinned stdlib a circuit could never recompute it from the source. In the signed message each byte value degrades to two fields, bytes 0-15 then bytes 16-31 as `Uint<128>`, so `K = 11 + 2V + 3W`; `W = 0` reproduces the numeric-only layout exactly.
