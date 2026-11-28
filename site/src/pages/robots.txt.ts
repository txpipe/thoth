// Lets every crawler in and names the sitemap. Crawlers read robots.txt only
// at a host's root, so under a project path such as /thoth/ they never fetch
// this file; it takes effect once the site is served from a domain of its own.
// Until then each page's head links the sitemap.

import type { APIRoute } from 'astro';
import { withBase } from '../lib/docs';

export const GET: APIRoute = () => {
  const site = import.meta.env.SITE;
  if (!site) throw new Error('Set `site` in astro.config.ts to generate robots.txt');

  const sitemap = new URL(withBase('/sitemap.xml', import.meta.env.BASE_URL), site).href;
  return new Response(`User-agent: *\nAllow: /\n\nSitemap: ${sitemap}\n`, {
    headers: { 'content-type': 'text/plain; charset=utf-8' },
  });
};
