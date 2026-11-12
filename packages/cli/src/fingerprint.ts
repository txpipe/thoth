// A hash of everything in the config that the generated files depend on. The
// generated `thoth.check.ts` recomputes it the same way from the loaded config.
import { createHash } from 'node:crypto';
import type { ThothConfig } from './config.js';

/**
 * The SHA-256, in hex, of the config's law, client entry, policy hash, layout,
 * app id, threshold, attestors and contract windows. The policy enters through
 * its hash, so an equivalent policy keeps the fingerprint.
 *
 * @throws whatever the kind's policy schema, `policyHashOf` or `layoutOf`
 *   throws for the config's policy.
 */
export function configFingerprint(config: ThothConfig): string {
  // Keep in step with fingerprintOf in emitCheck's output (emit-ts.ts).
  const policy = config.kind.policySchema.parse(config.policy);
  const layout = config.kind.layoutOf(policy);
  const json = JSON.stringify([
    config.kind.law,
    [config.kind.clientEntry.module, config.kind.clientEntry.export],
    Buffer.from(config.kind.policyHashOf(policy)).toString('hex'),
    [
      layout.valueSlots,
      layout.byteSlots,
      layout.names.map((slot) => [slot.name, slot.region, slot.index, slot.optional]),
    ],
    config.appId.toLowerCase().replace(/^0x/, ''),
    config.threshold,
    config.attestors.map(({ id, publicKey }) => [id, `${publicKey.x}`, `${publicKey.y}`]),
    [config.contract.freshnessWindow, config.contract.maxWindow],
  ]);
  return createHash('sha256').update(json).digest('hex');
}
