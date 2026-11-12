// The built `@thoth/zk-tls/client` statically imports none of the attestor side,
// which `./attestor`, `./dev` and `./thoth` load.
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const STATIC_IMPORT = /(?:^|\n)\s*(?:import|export)\s(?:[^;'"]*?\sfrom\s*)?['"]([^'"]+)['"]/g;
const WORKSPACE_PACKAGE = /^@thoth\//;

/** Every file and bare package an entry loads through static imports, transitively. */
const staticGraphOf = (entry: string): { files: Set<string>; packages: Set<string> } => {
  const files = new Set<string>();
  const packages = new Set<string>();
  const visit = (file: string): void => {
    if (files.has(file)) return;
    files.add(file);
    for (const [, specifier] of readFileSync(file, 'utf-8').matchAll(STATIC_IMPORT)) {
      if (specifier === undefined) continue;
      if (specifier.startsWith('.')) {
        visit(resolve(dirname(file), specifier));
        continue;
      }
      packages.add(specifier);
      if (WORKSPACE_PACKAGE.test(specifier)) visit(fileURLToPath(import.meta.resolve(specifier)));
    }
  };
  visit(fileURLToPath(import.meta.resolve(entry)));
  return { files, packages };
};

describe('@thoth/zk-tls/client', () => {
  const { files, packages } = staticGraphOf('@thoth/zk-tls/client');

  it('loads no attestor-side package', () => {
    expect(packages.size).toBeGreaterThan(0);
    for (const attestorSide of [
      '@thoth/attestor',
      '@reclaimprotocol/attestor-core',
      '@reclaimprotocol/tls',
    ]) {
      expect(packages).not.toContain(attestorSide);
    }
  });

  it('loads none of the attestor, dev or thoth entries', () => {
    const entries = [...files].map((file) => file.split('/dist/')[1]);
    expect(entries).toContain('client/index.js');
    expect(entries.filter((file) => /^(attestor|dev|thoth)\//.test(file ?? ''))).toEqual([]);
  });
});
