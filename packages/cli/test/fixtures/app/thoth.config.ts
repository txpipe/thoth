// The test app's config: a Strava-style zkFetch policy and three dev attestors,
// 2-of-3. The test copies it into a temp project and fills in the modules path.
import { defineConfig } from '@thoth/cli';
import { zkTls } from '@thoth/zk-tls/thoth';
import { devKeyPair } from './keys.ts';

export default defineConfig({
  kind: zkTls,
  policy: {
    allowedHosts: ['www.strava.com'],
    bodyPolicy: 'ignored',
    slots: [
      { slot: 0, name: 'distance', parse: 'int' },
      { slot: 1, name: 'movingTime', parse: 'int', optional: true },
      { slot: 2, name: 'athlete', parse: 'bytes' },
    ],
    responseMatches: [
      { type: 'regex', value: '"distance":\\s*(?<distance>\\d+)' },
      { type: 'regex', value: '"moving_time":\\s*(?<movingTime>\\d+)' },
      { type: 'regex', value: '"athlete":\\s*"(?<athlete>[^"]+)"' },
    ],
    responseRedactions: [
      { regex: '"distance":\\s*\\d+' },
      { regex: '"moving_time":\\s*\\d+' },
      { regex: '"athlete":\\s*"[^"]+"' },
    ],
  },
  appId: 'a1'.repeat(32),
  threshold: 2,
  attestors: [0, 1, 2].map((i) => ({ id: `dev-${i}`, publicKey: devKeyPair(i).publicKey })),
  contract: {
    source: 'contract/app.compact',
    modules: '__MODULES__',
    freshnessWindow: 86400,
    maxWindow: 300,
  },
  out: { compact: 'contract/generated', ts: 'src/generated', artifacts: 'artifacts/app' },
});
