// Drive: a dApp collecting an N-of-M attestment through `@thoth/zk-tls/client` over its
// `@thoth/client` trusted set, with each operator's prover replaying the recorded evidence.
import { descriptorOf } from '@thoth/attestor';
import { buildTrustedSet } from '@thoth/client';
import { jubjubVerifier } from '@thoth/client/jubjub';
import { attestorNamed, collectOptions, dapp, HOLDER, main, request } from './common.mjs';

/** What a dApp checks on an attestment before it submits. */
const summary = async ({ claim, message, collected, failures }) => ({
  claim,
  messageLength: message.length,
  slots: collected.map((entry) => entry.registryIndex),
  sameMessage: collected.every((entry) =>
    entry.attestation.message.every((field, i) => field === message[i]),
  ),
  signaturesVerify: await Promise.all(
    collected.map(({ attestation: a }) =>
      jubjubVerifier.verify(a.publicKey, a.message, a.signature),
    ),
  ),
  ...(failures === undefined ? {} : { failures }),
});

/** A reply whose signature is another valid-looking one, as a broken transport returns. */
const forgeOperatorB = (id, reply) =>
  id === 'operator-b'
    ? { ...reply, signature: { ...reply.signature, response: reply.signature.response + 1n } }
    : reply;

await main({
  collect: async () => summary(await dapp().client.collect(request, collectOptions())),
  'prove-attest': async () => {
    const proof = await dapp().client.proveReq(request, HOLDER);
    return summary(await proof.attest());
  },
  'forged-collect': async () =>
    summary(await dapp({ tamper: forgeOperatorB }).client.collect(request, collectOptions())),
  'forged-attest': async () => {
    const proof = await dapp({ tamper: forgeOperatorB }).client.proveReq(request, HOLDER);
    return summary(await proof.attest());
  },
  'other-origin': async () =>
    dapp().client.proveReq({ ...request, url: 'https://example.com/repos/x' }, HOLDER),
  expired: async () =>
    dapp().client.collect(request, collectOptions({ expiresAt: Date.now() - 1 })),
  'threshold-too-high': async () =>
    dapp().client.collect(request, collectOptions({ threshold: 3 })),
  'duplicate-slot': async () => {
    return buildTrustedSet({
      registrySize: 3,
      attestors: [
        { attestor: descriptorOf(attestorNamed('operator-a')), registryIndex: 0 },
        { attestor: descriptorOf(attestorNamed('operator-b')), registryIndex: 0 },
      ],
    });
  },
  'slot-outside-registry': async () =>
    buildTrustedSet({
      registrySize: 3,
      attestors: [{ attestor: descriptorOf(attestorNamed('operator-a')), registryIndex: 3 }],
    }),
});
