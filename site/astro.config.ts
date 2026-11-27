import { fileURLToPath } from 'node:url';
import { rehypeHeadingIds, unified } from '@astrojs/markdown-remark';
import { defineConfig } from 'astro/config';
import { headingLinks } from './src/lib/heading-links';
import { retitle } from './src/lib/retitle';
import { rewriteLinks } from './src/lib/rewrite-links';
import { wrapTables } from './src/lib/wrap-tables';

const site = 'https://txpipe.github.io';
const base = '/thoth';
const repoRoot = fileURLToPath(new URL('..', import.meta.url));

export default defineConfig({
  site,
  base,
  trailingSlash: 'always',
  markdown: {
    shikiConfig: { theme: 'synthwave-84' },
    processor: unified({
      remarkPlugins: [
        [rewriteLinks, { repoRoot, base }],
        [retitle, { repoRoot }],
      ],
      rehypePlugins: [rehypeHeadingIds, headingLinks, wrapTables],
    }),
  },
});
