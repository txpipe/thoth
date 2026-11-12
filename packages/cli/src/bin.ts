#!/usr/bin/env node
// The `thoth` command: generate the app's Thoth embedding from thoth.config.ts,
// and compile the app contract against the Thoth modules.
import { relative } from 'node:path';
import { compile } from './compile.js';
import { generate } from './generate.js';

const USAGE = `Usage: thoth <command> [--config <path>]

Commands:
  generate            Write the Compact and TypeScript files the config implies
  compile [flags]     Compile the app contract; flags such as --skip-zk go to compact compile

Options:
  --config <path>     The config file (default: thoth.config.ts)
`;

const main = async (argv: readonly string[]): Promise<number> => {
  const [command, ...rest] = argv;
  let configPath = 'thoth.config.ts';
  const args: string[] = [];
  for (let i = 0; i < rest.length; i++) {
    const arg = rest[i] as string;
    if (arg === '--config') {
      const value = rest[++i];
      if (value === undefined) {
        throw new Error('--config needs a path');
      }
      configPath = value;
    } else {
      args.push(arg);
    }
  }
  switch (command) {
    case 'generate': {
      if (args.length > 0) {
        throw new Error(`generate takes no arguments, got ${args.join(' ')}`);
      }
      for (const path of await generate(configPath)) {
        console.log(`wrote ${relative(process.cwd(), path)}`);
      }
      return 0;
    }
    case 'compile':
      return compile(configPath, args);
    case undefined:
    case '--help':
    case 'help':
      process.stdout.write(USAGE);
      return command === undefined ? 1 : 0;
    default:
      throw new Error(`unknown command '${command}'\n\n${USAGE}`);
  }
};

try {
  process.exitCode = await main(process.argv.slice(2));
} catch (error) {
  process.stderr.write(`thoth: ${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
}
