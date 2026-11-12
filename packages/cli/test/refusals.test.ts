// What `thoth generate` and the generated config check refuse: an edited or
// foreign file at a generated path, a name clash with the app contract, and a
// config that changed since the last `generate`.
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
