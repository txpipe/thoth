// What prove.ts and check.ts share: the request, the run's paths and the City API token.
import { readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { parseEnv } from 'node:util';

/** The City's authenticated, read-only list of the agents a token controls. */
export const CLAIMABLE_URL = 'https://midnight.city/observer/api/local-control/claimable';

/** Hermes's skill env file. Read in-process only; the token is never printed. */
const HERMES_ENV = join(homedir(), '.hermes', 'skills', 'midnight-city-direct-control', '.env');

/** Local run output, gitignored: fresh evidence works as a bearer token until #134 is fixed. */
const STATE_DIR = new URL('../.state/', import.meta.url);

/** The evidence pair prove.ts writes and check.ts verifies. */
export const EVIDENCE_PATH = new URL('evidence.json', STATE_DIR);

/** prove.ts's whole output, Reclaim client logs included; `npm start` redirects it here. */
export const RUN_LOG_PATH = new URL('run.log', STATE_DIR);

/**
 * Load the City API token from Hermes's skill env file.
 *
 * @returns the token.
 * @throws if the file lacks `MCITY_API_TOKEN`.
 */
export const loadToken = (): string => {
  const token = parseEnv(readFileSync(HERMES_ENV, 'utf8')).MCITY_API_TOKEN;
  if (token === undefined || token === '') {
    throw new Error(`MCITY_API_TOKEN is not set in ${HERMES_ENV}`);
  }
  return token;
};
