// Plain-string Cardano fixture constants shared between `cardano` unit tests
// and `contracts` cross-seam acceptance tests, with zero Cardano dependencies.

/** A preview payment address at the smallest CIP-19 length; the checksum is a fixture. */
export const CARDANO_TEST_ADDRESS = `addr_test1${'q'.repeat(53)}`;

/** Fixed 32-byte transaction hash fixture (lowercase hex). */
export const CARDANO_TX_HASH = 'cd'.repeat(32);

/** Fixed 32-byte block hash fixture (lowercase hex). */
export const CARDANO_BLOCK_HASH = 'ab'.repeat(32);
