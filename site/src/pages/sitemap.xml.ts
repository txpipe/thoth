// The sitemap: every published doc at its canonical address, in nav order.

import type { APIRoute } from 'astro';
import { getDocs, navGroups } from '../lib/collection';
import { withBase } from '../lib/docs';

const xml = (text: string) =>
  text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

export const GET: APIRoute = async () => {
  const site = import.meta.env.SITE;
  if (!site) throw new Error('Set `site` in astro.config.ts to generate sitemap.xml');

  const base = import.meta.env.BASE_URL;
  const urls = navGroups(await getDocs())
    .flatMap((group) => group.items)
    .map((item) => new URL(withBase(item.route, base), site).href)
    .map((url) => `  <url><loc>${xml(url)}</loc></url>`);

  return new Response(
    `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${urls.join('\n')}\n</urlset>\n`,
    { headers: { 'content-type': 'application/xml; charset=utf-8' } },
  );
};
