# GitHub repository stars

The star count of a public GitHub repository, read from the REST API.

## Source

`GET https://api.github.com/repos/{owner}/{repo}` on the
[GitHub REST API](https://docs.github.com/en/rest/repos/repos#get-a-repository).
The endpoint is public, and GitHub rate-limits unauthenticated requests per
address.

## Request

- Method: `GET`.
- URL: `https://api.github.com/repos/txpipe/dolos`.
- Public headers: `accept: application/vnd.github+json`, `user-agent: thoth-docs`.
- Secret headers: none.
- Body: the sentinel `{"thoth":"ignored"}`. The API ignores it, and the policy
  pins it.

## Policy

```ts
import { zkFetchBodyHashOf, type ZkFetchPolicy } from '@thoth/zk-tls';

const SENTINEL = '{"thoth":"ignored"}';

export const policy: ZkFetchPolicy = {
  allowedHosts: ['api.github.com'],
  slots: [{ slot: 0, name: 'stars', parse: 'int' }],
  responseMatches: [{ type: 'regex', value: '"stargazers_count":\\s*(?<stars>\\d+)' }],
  responseRedactions: [{ regex: '"stargazers_count":\\s*\\d+' }],
  bodyPolicy: { sha256: zkFetchBodyHashOf(SENTINEL) },
};
```

The contract needs one value slot (`#V` 1) and no byte slots. It seals
`zkFetchPolicyHashOf(policy)`.

## What it certifies

At the witness's observation time, GitHub returned that `stargazers_count` for
the repository in the request. The number is GitHub's count of accounts that
starred it; the claim does not say who starred it or when.

## Limits

- The count changes with every star, so the claim is only as fresh as the
  [window](../../CONTEXT.md#the-claim).
- The policy binds the host, not the repository path. The full URL is in the
  claim's subject, so your contract must pin the repository it accepts
  ([ADR 0001](../adr/0001-source-binding-by-in-circuit-subject-hash.md)).
- The unauthenticated API is rate-limited per address; a limited witness fails
  the attempt with `evidence`
  ([Guarantees and limits](../../packages/zk-tls/README.md#guarantees-and-limits)).
- GitHub counts accounts, not people, and it does not remove every automated
  star. A star count is not a measure of real users.
- The request needs no credentials. Do not add a token: every witness would see
  it as a secret header, and the policy gains no assurance about who starred
  the repository.
