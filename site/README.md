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

Search runs on a [Pagefind](https://pagefind.app) index that `npm run build`
writes to `dist/pagefind` after Astro builds. `npm run dev` has no index, so
search there says to build and preview instead:

```bash
npm run build --prefix site
npm run preview --prefix site
```

Astro caches rendered Markdown between builds and does not notice a change to
a remark or rehype plugin in `src/lib/`. After you edit one, delete
`site/node_modules/.astro` before you build.
