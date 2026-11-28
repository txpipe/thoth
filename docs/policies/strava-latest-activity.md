# Strava latest activity

The distance and moving time of the newest activity in a Strava athlete's list.

## Source

`GET https://www.strava.com/api/v3/athlete/activities?per_page=1` on the
[Strava v3 API](https://developers.strava.com/docs/reference/). The endpoint
needs an OAuth token for the athlete.

## Request

- Method: `GET`.
- URL: `https://www.strava.com/api/v3/athlete/activities?per_page=1`.
- Public headers: `accept: application/json`.
- Secret headers: `authorization: Bearer <token>`.
- Body: none. The policy sets `bodyPolicy: 'ignored'`.

## Policy

```ts
import type { ZkFetchPolicy } from '@txpipe/thoth-zk-tls';

export const policy: ZkFetchPolicy = {
  allowedHosts: ['www.strava.com'],
  slots: [
    { slot: 0, name: 'distance', parse: 'float' },
    { slot: 1, name: 'movingTime', parse: 'int' },
  ],
  responseMatches: [
    { type: 'regex', value: '"distance":\\s*(?<distance>[\\d.]+)' },
    { type: 'regex', value: '"moving_time":\\s*(?<movingTime>\\d+)' },
  ],
  responseRedactions: [{ regex: '"distance":\\s*[\\d.]+' }, { regex: '"moving_time":\\s*\\d+' }],
  // Safe only if no layer in front of the endpoint can change its response
  // based on a request body.
  bodyPolicy: 'ignored',
};
```

The contract needs two value slots (`#V` 2) and no byte slots. It seals
`zkFetchPolicyHashOf(policy)`. `zkFetchClient.init` parses the policy with
`zkFetchPolicySchema`, so a regex that RE2 rejects fails before any fetch.

## What it certifies

At the witness's observation time, Strava returned the newest activity in the
token holder's list. Slot 0 is its distance in metres, and slot 1 is its moving
time in seconds.

## Limits

- The OAuth token identifies the athlete, not a Midnight key. The claim binds
  the token holder; your app must bind the Strava account to its own identity
  before it accepts the claim.
- `authorization` is a secret header. Every witness sees it, and the client
  refuses evidence that carries its value
  ([Guarantees and limits](../../packages/zk-tls/README.md#guarantees-and-limits)).
  A very short token can match unrelated text and drop a healthy attestor.
- `bodyPolicy: 'ignored'` does not bind the request body, and a GET can carry
  one. Use it only when no layer in front of the endpoint can change the
  response from a body; otherwise use `non-empty` or a pinned sentinel
  ([Body policy](../../packages/zk-tls/docs/dapp-integration.md#body-policy)).
- The list is newest-first at the moment of the fetch. A later upload or edit
  changes what "latest" means, and the claim is only as fresh as the window.
- Strava rate-limits the API; a refused fetch fails the attempt with `evidence`.
