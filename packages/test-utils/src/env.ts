// Shared environment-variable parsing helpers for opt-in live test suites.

/**
 * Parse a comma-separated environment variable into trimmed, non-empty entries.
 * Unset, blank, or comma-only values yield an empty array so live suites skip.
 */
export const parseEnvList = (
  name: string,
  env: Readonly<Record<string, string | undefined>> = process.env,
): string[] =>
  (env[name] ?? '')
    .split(',')
    .map((entry) => entry.trim())
    .filter((entry) => entry !== '');

/**
 * Parse a single URL environment variable; unset, blank, or comma-only values
 * yield `''` so live suites skip.
 */
export const parseEnvUrl = (
  name: string,
  env: Readonly<Record<string, string | undefined>> = process.env,
): string => {
  const value = env[name]?.trim() ?? '';
  return /^[\s,]*$/.test(value) ? '' : value;
};
