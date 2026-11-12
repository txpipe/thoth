// A temp app project built from `fixtures/app`, and the built `thoth` bin run
// inside it. The project links the repo's node_modules, so its config and the
// generated files resolve the workspace packages.
import { spawnSync } from 'node:child_process';
import {
  cpSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const repo = resolve(here, '..', '..', '..', '..');
const bin = join(repo, 'packages', 'cli', 'dist', 'bin.js');
const tsc = join(repo, 'node_modules', 'typescript', 'bin', 'tsc');

/** A temp copy of the fixture app. */
export interface Project {
  readonly dir: string;
  /** Absolute path of a file in the project. */
  path(relative: string): string;
  read(relative: string): string;
  write(relative: string, content: string): void;
  /** Run the built `thoth` bin with `args`, from the project directory. */
  thoth(...args: string[]): { status: number | null; stdout: string; stderr: string };
  /** Type-check the project, generated files included, with the repo's strict settings. */
  typeCheck(): { status: number | null; stdout: string };
  /** Delete the project. */
  remove(): void;
}

export function makeProject(): Project {
  const dir = mkdtempSync(join(tmpdir(), 'thoth-cli-'));
  cpSync(join(here, '..', 'fixtures', 'app'), dir, { recursive: true });
  symlinkSync(join(repo, 'node_modules'), join(dir, 'node_modules'), 'dir');
  writeFileSync(join(dir, 'package.json'), '{ "type": "module" }\n');
  const config = join(dir, 'thoth.config.ts');
  writeFileSync(
    config,
    readFileSync(config, 'utf8').replace('__MODULES__', join(repo, 'packages', 'contracts')),
  );
  writeFileSync(
    join(dir, 'tsconfig.json'),
    JSON.stringify({
      extends: join(repo, 'tsconfig.base.json'),
      compilerOptions: { noEmit: true, allowImportingTsExtensions: true },
      include: ['*.ts', 'src/**/*.ts'],
    }),
  );
  const path = (relative: string) => join(dir, relative);
  return {
    dir,
    path,
    read: (relative) => readFileSync(path(relative), 'utf8'),
    write: (relative, content) => {
      mkdirSync(dirname(path(relative)), { recursive: true });
      writeFileSync(path(relative), content);
    },
    thoth: (...args) => {
      const run = spawnSync(process.execPath, [bin, ...args], { cwd: dir, encoding: 'utf8' });
      return { status: run.status, stdout: run.stdout, stderr: run.stderr };
    },
    typeCheck: () => {
      const run = spawnSync(process.execPath, [tsc, '-p', dir], { encoding: 'utf8' });
      return { status: run.status, stdout: run.stdout };
    },
    remove: () => rmSync(dir, { recursive: true, force: true }),
  };
}
