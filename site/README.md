# Thoth docs site

The Astro site renders the repo's reader-facing Markdown at build time. It is
its own npm project and is not a root workspace.

```bash
npm ci --prefix site
npm run dev --prefix site
```

`src/lib/docs.ts` is the publish allowlist; the site holds no copy of the docs.
Run `npm run check --prefix site` and `npm run build --prefix site` before you
push.
