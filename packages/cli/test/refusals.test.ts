// What `thoth generate`, `thoth compile` and the generated config check refuse:
// edited or foreign generated files, name clashes, and a config changed since `generate`.
import { existsSync } from 'node:fs';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { makeProject, type Project } from './helpers/project.js';

let project: Project;

beforeEach(() => {
  project = makeProject();
});

afterEach(() => project.remove());

const generateOk = () => {
  const run = project.thoth('generate');
  expect(run.stderr).toBe('');
  expect(run.status).toBe(0);
};

describe('thoth generate', () => {
  it('rewrites its own unedited output', () => {
    generateOk();
    generateOk();
  });

  it.each([
    'contract/generated/thoth.compact',
    'src/generated/thoth.ts',
    'src/generated/thoth.check.ts',
  ])('refuses to overwrite %s once it was edited, and writes nothing', (file) => {
    generateOk();
    const edited = `${project.read(file)}// my change\n`;
    project.write(file, edited);
    project.write(
      'thoth.config.ts',
      project.read('thoth.config.ts').replace('threshold: 2', 'threshold: 3'),
    );
    const run = project.thoth('generate');
    expect(run.status).toBe(1);
    expect(run.stderr).toContain(`${file} was edited since thoth generate wrote it`);
    expect(project.read(file)).toBe(edited);
    // The other files still describe the 2-of-3 config.
    expect(project.read('contract/generated/thoth.compact')).toContain('2-of-3');
  });

  it('refuses to overwrite a file it did not write', () => {
    project.write('contract/generated/thoth.compact', '// mine\n');
    const run = project.thoth('generate');
    expect(run.status).toBe(1);
    expect(run.stderr).toContain('thoth.compact was not written by thoth generate');
  });

  it('refuses an app contract that declares a generated name, and writes nothing', () => {
    project.write(
      'contract/app.compact',
      `${project.read('contract/app.compact')}\ncircuit athleteOf(x: Field): Field { return x; }\n`,
    );
    const run = project.thoth('generate');
    expect(run.status).toBe(1);
    expect(run.stderr).toContain(
      "the app contract declares 'athleteOf', which thoth generate also declares",
    );
    expect(existsSync(project.path('contract/generated/thoth.compact'))).toBe(false);
  });

  it('refuses an attestor key pinned twice', () => {
    project.write(
      'thoth.config.ts',
      project
        .read('thoth.config.ts')
        .replace('devKeyPair(i).publicKey', 'devKeyPair(i === 2 ? 1 : i).publicKey'),
    );
    const run = project.thoth('generate');
    expect(run.status).toBe(1);
    expect(run.stderr).toContain("attestor 2 ('dev-2'): its public key is pinned twice");
  });
});

describe('thoth compile', () => {
  it('refuses a config changed since the last generate, before compiling', () => {
    generateOk();
    project.write(
      'thoth.config.ts',
      project.read('thoth.config.ts').replace('threshold: 2', 'threshold: 3'),
    );
    const run = project.thoth('compile', '--skip-zk');
    expect(run.status).toBe(1);
    expect(run.stderr).toContain('thoth.config.ts changed since the last `thoth generate`');
    expect(existsSync(project.path('artifacts'))).toBe(false);
  });

  it('refuses a generated Compact file that was edited', () => {
    generateOk();
    const file = 'contract/generated/thoth.compact';
    project.write(file, `${project.read(file)}// my change\n`);
    const run = project.thoth('compile', '--skip-zk');
    expect(run.status).toBe(1);
    expect(run.stderr).toContain(`${file} was edited since thoth generate wrote it`);
  });

  it('refuses to compile before generate', () => {
    const run = project.thoth('compile', '--skip-zk');
    expect(run.status).toBe(1);
    expect(run.stderr).toContain('run thoth generate first');
  });
});

describe('the generated config check', () => {
  it('refuses a config changed since the last generate', async () => {
    generateOk();
    project.write(
      'thoth.config.ts',
      project.read('thoth.config.ts').replace('freshnessWindow: 86400', 'freshnessWindow: 3600'),
    );
    await expect(import(project.path('src/generated/thoth.check.ts'))).rejects.toThrow(
      'thoth.config.ts changed since the last `thoth generate`',
    );
  });
});
