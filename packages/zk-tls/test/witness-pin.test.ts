// The witness script, the attestor guide and the library must run the same
// attestor-core release. A dependency bump fails here until the script is re-pinned.
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

/**
 * The attestor-core commit the live check passed against, per release. Add the
 * new release's commit here once the live check passes on it.
 */
const VERIFIED_PINS: Readonly<Record<string, string>> = {
  '5.1.6': 'f451eb3c3038efcf7c11b2497d7540d8f1e95752',
};

const packageRoot = new URL('../', import.meta.url);
const read = (path: string) => readFileSync(new URL(path, packageRoot), 'utf8');

const script = read('scripts/start-witnesses.sh');
const pinnedVersion = /^PINNED_VERSION=(\S+)$/m.exec(script)?.[1];
const pinnedRef = /^PINNED_REF="\$\{WITNESS_REF:-(\S+)\}"$/m.exec(script)?.[1];

describe('witness pin', () => {
  it('pins the witness to the attestor-core version @thoth/zk-tls depends on', () => {
    const manifest = JSON.parse(read('package.json')) as {
      dependencies: Record<string, string>;
    };
    expect(pinnedVersion, 'PINNED_VERSION in start-witnesses.sh').toBeDefined();
    expect(manifest.dependencies['@reclaimprotocol/attestor-core']).toBe(pinnedVersion);
  });

  it('pins the full commit verified for that version', () => {
    expect(pinnedRef, 'PINNED_REF in start-witnesses.sh').toMatch(/^[0-9a-f]{40}$/);
    expect(VERIFIED_PINS[pinnedVersion ?? ''], `verified commit for ${pinnedVersion}`).toBe(
      pinnedRef,
    );
  });

  it("checks out the script's commit in the attestor guide's manual setup", () => {
    expect(read('docs/attestor-guide.md')).toContain(`git checkout --detach ${pinnedRef}`);
  });

  it('moves the commit with every version', () => {
    const refs = Object.values(VERIFIED_PINS);
    expect(new Set(refs).size).toBe(refs.length);
  });
});
