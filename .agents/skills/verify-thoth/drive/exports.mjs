// Drive: the package entry points a consumer imports, resolved and loaded the way
// `import '@thoth/...'` does in an app that installed the packages.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { main } from './common.mjs';

const root = new URL('../../../../', import.meta.url);
const readJson = (path) => JSON.parse(readFileSync(new URL(path, root), 'utf-8'));
const repo = fileURLToPath(root);

/** Every `exports` entry of every workspace, as the specifier a consumer writes. */
const specifiers = () =>
  readJson('package.json').workspaces.flatMap((workspace) => {
    const manifest = readJson(`${workspace}/package.json`);
    return Object.keys(manifest.exports ?? {}).map((key) => manifest.name + key.slice(1));
  });

await main({
  resolve: async () =>
    Promise.all(
      specifiers().map(async (specifier) => ({
        specifier,
        resolved: fileURLToPath(import.meta.resolve(specifier)).replace(repo, ''),
        exports: Object.keys(await import(specifier)).sort(),
      })),
    ),
  // A file inside the package that its `exports` map does not name.
  private: async () => import('@thoth/core/dist/claim.js'),
});
