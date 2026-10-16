# Encoded byte rules decode and normalize the source representation

Status: accepted

The policy's byte rules fill a 32-byte claim slot from the disclosed string (ADR 0009). Alongside the literal `bytes` rule, `hex` and `base64` decode the string into its bytes, so representations of the same information certify one claim value: hex case, an optional `0x`/`0X` marker, the base64 standard and URL-safe alphabets, and optional base64 `=` padding all fold together. Padding-only and trailing-bit-invalid encodings are rejected rather than folded, so a leniently decoded `AB==` cannot collapse into `AA==`.

Decoding is deterministic — client and attestors share the law — and never deletes a character. Separators, whitespace and punctuation are part of the value: a hyphenated identifier is not its unhyphenated form, `AA:BB` is not hex, and a wrapped encoding is invalid rather than normalized. This rejected separator stripping deliberately: for identifiers the separator may carry the meaning.

A slot may additionally pin the exact byte length of the value (`length`, 1–32): the UTF-8 length for `bytes`, the decoded length for `hex`/`base64`. The pin keeps the zero padding from making differently-sized values collide, so a 21-byte value ending in `00` cannot stand in for a pinned 20-byte address.

The wire is unchanged: a decoded value is still exactly 32 bytes (ADR 0009), and none of this is visible to the contract. Deferred: base32/base58, and decoded values longer than 32 bytes (split across two slots with separate named groups).
