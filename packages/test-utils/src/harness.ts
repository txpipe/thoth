// Kind-agnostic SDK test harnesses using structural types, with zero runtime
// dependencies on any `@txpipe/thoth-*` package.

/** Fake public key carrying only the attestor id, for offline client tests. */
export type FakePublicKey = { readonly id: string };

/** Fake signature string encoding only the signed message length. */
export type FakeSignature = string;

/** Structural key pair matching `@txpipe/thoth-attestor`'s `KeyPair`. */
export interface FakeKeyPair {
  readonly publicKey: FakePublicKey;
  readonly signer: {
    sign(message: readonly bigint[]): FakeSignature;
  };
}

/** Structural verifier matching `@txpipe/thoth-client`'s `AttestationVerifier`. */
export interface FakeVerifier {
  verify(key: FakePublicKey, message: readonly bigint[], signature: FakeSignature): boolean;
}

/** Build a fake key pair whose signer produces `sig:<message.length>`. */
export const fakeKeyPair = (id: string): FakeKeyPair => ({
  publicKey: { id },
  signer: { sign: (message) => `sig:${message.length}` },
});

/**
 * Build a fake verifier that accepts `sig:<message.length>` for every key whose
 * id is not in `rejected`.
 */
export const fakeVerifier = (rejected: readonly string[] = []): FakeVerifier => ({
  verify: (key, message, signature) =>
    !rejected.includes(key.id) && signature === `sig:${message.length}`,
});

/** Structural view of an attestor instance routed by {@link inMemoryTransport}. */
export interface AttestorLike<I = never, O = unknown> {
  readonly id: string;
  attest(input: I): Promise<O>;
}

/**
 * Build an in-memory transport that dispatches requests to `attestors` by id.
 *
 * @throws if the descriptor names an attestor not in `attestors`.
 */
export const inMemoryTransport = <I, O>(
  attestors: readonly AttestorLike<I, O>[],
): {
  request(descriptor: { readonly id: string }, input: I): Promise<O>;
} => {
  const byId = new Map(attestors.map((attestor) => [attestor.id, attestor]));
  return {
    request: (descriptor, input) => {
      const attestor = byId.get(descriptor.id);
      if (attestor === undefined) {
        throw new Error(`transport: unknown attestor ${descriptor.id}`);
      }
      return attestor.attest(input);
    },
  };
};

/** Structural view of an attestor projected into a client descriptor. */
export interface AttestorDescriptorLike<D = unknown, PK = unknown> {
  readonly id: string;
  readonly definition: D;
  readonly publicKey: PK;
}

/**
 * Build a trusted set from `attestors` using the caller's `buildTrustedSet`,
 * assigning slots `0..N-1` unless `options.slots` overrides them.
 *
 * @throws if `options.slots` length does not match `attestors.length`.
 */
export const trustedSetOf = <D, PK, TSet>(
  buildTrustedSet: (options: {
    readonly registrySize: number;
    readonly attestors: readonly {
      readonly attestor: { id: string; definition: D; publicKey: PK };
      readonly registryIndex: number;
    }[];
  }) => TSet,
  attestors: readonly AttestorDescriptorLike<D, PK>[],
  options: { readonly registrySize?: number; readonly slots?: readonly number[] } = {},
): TSet => {
  const registrySize = options.registrySize ?? attestors.length;
  const slots = options.slots ?? attestors.map((_, index) => index);
  if (slots.length !== attestors.length) {
    throw new Error(`trustedSetOf: expected ${attestors.length} slots, got ${slots.length}`);
  }
  return buildTrustedSet({
    registrySize,
    attestors: attestors.map((attestor, index) => {
      const registryIndex = slots[index];
      if (registryIndex === undefined) {
        throw new Error(`trustedSetOf: missing slot for index ${index}`);
      }
      return {
        attestor: {
          id: attestor.id,
          definition: attestor.definition,
          publicKey: attestor.publicKey,
        },
        registryIndex,
      };
    }),
  });
};

/** Return the registry slot indices of an attestment's collected attestations. */
export const collectedSlots = (attestment: {
  readonly collected: readonly { readonly registryIndex: number }[];
}): number[] => attestment.collected.map((entry) => entry.registryIndex);
