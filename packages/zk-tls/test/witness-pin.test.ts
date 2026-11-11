// The witness script and the library must run the same attestor-core release.
// A dependency bump fails here until scripts/start-witnesses.sh is re-pinned.
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const packageRoot = new URL('../', import.meta.url);

describe('witness pin', () => {
  it('pins the witness to the attestor-core version @thoth/zk-tls depends on', () => {
    const manifest = JSON.parse(readFileSync(new URL('package.json', packageRoot), 'utf8')) as {
      dependencies: Record<string, string>;
    };
    const script = readFileSync(new URL('scripts/start-witnesses.sh', packageRoot), 'utf8');

    const pinned = /^PINNED_VERSION=(\S+)$/m.exec(script)?.[1];
    expect(pinned, 'PINNED_VERSION in start-witnesses.sh').toBeDefined();
    expect(manifest.dependencies['@reclaimprotocol/attestor-core']).toBe(pinned);
  });
});
