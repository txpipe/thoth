import { fileURLToPath } from 'node:url';
import { unified } from '@astrojs/markdown-remark';
import { defineConfig } from 'astro/config';
import { rewriteLinks } from './src/lib/rewrite-links';

const site = 'https://txpipe-shop.github.io';
const base = '/thoth';
const repoRoot = fileURLToPath(new URL('..', import.meta.url));

export default defineConfig({
  site,
  base,
  trailingSlash: 'always',
  markdown: {
    processor: unified({
      remarkPlugins: [[rewriteLinks, { repoRoot, base }]],
    }),
  },
});
