// Runs in the vitest process. When that process is stopped, its watchdog kills the worker with
// SIGKILL, which no handler survives, so this process removes the run's proof servers itself.
import { dockerOptions, RUN_ENV } from './options.js';
import { removeRunContainers } from './proof-server.js';

/** Label this run's containers and remove them on any exit of the vitest process. */
export default (): (() => void) | undefined => {
  if (process.env.PROOF_SERVER_URL) {
    return undefined;
  }
  // The worker inherits this, and labels every container it starts with it.
  process.env[RUN_ENV] = String(process.pid);
  const docker = dockerOptions(process.env);
  // Vitest ends with `process.exit` on SIGINT and SIGTERM, which runs `exit` handlers.
  const remove = () => removeRunContainers(docker);
  process.on('exit', remove);
  return () => {
    process.off('exit', remove);
    remove();
  };
};
