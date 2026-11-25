# @txpipe/thoth-test-utils

Private shared test utilities for Thoth workspace suites.

> **In development.** Thoth is unaudited and has [known security issues](https://github.com/txpipe-shop/thoth/issues?q=is%3Aissue+is%3Aopen+label%3Asecurity). Don't use it to protect real value. The claim format may still change.

## Install

This package is private to the monorepo (`"private": true`) and is hoisted to
the root `node_modules/` by npm workspaces. Import its subpath `.ts` modules
directly from workspace test files without adding it to any published package's
`package.json`.

## Usage

```ts
import { filled, hex, padded32 } from '@txpipe/thoth-test-utils/bytes';
import { fakeKeyPair, fakeVerifier, inMemoryTransport } from '@txpipe/thoth-test-utils/harness';
import { jubjubKeyPair } from '@txpipe/thoth-test-utils/jubjub';
```

## Guarantees and limits

- **Zero workspace dependencies**: this package has no runtime dependencies on
  `@txpipe/thoth-*`, Compact artifacts, Reclaim, or Cardano libraries.
- **No build step**: subpath exports point directly to `.ts` source files and
  are type-checked via `npm run types` without emitting a `dist/` directory.
- **Test-only**: never import `@txpipe/thoth-test-utils` from production `src/`
  code.

## Design decisions

- **Subpath `.ts` exports without a build step**: keeps the workspace build
  chain unchanged and lets published packages stay free of private dev
  dependencies.
- **Structural types for SDK harnesses**: `inMemoryTransport`, `trustedSetOf`,
  and `createTestWitness` use structural interfaces instead of importing
  `@txpipe/thoth-*` or `@reclaimprotocol/attestor-core`, preventing dependency
  cycles.

## Links

- [Contributor guide](../../CONTRIBUTING.md#test-helpers)
- [Glossary](../../CONTEXT.md)
