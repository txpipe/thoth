import type { APIRoute } from 'astro';
import { getDocs, navGroups } from '../lib/collection';
import { summaryOf, withBase } from '../lib/docs';

export const GET: APIRoute = async () => {
  const site = import.meta.env.SITE;
  if (!site) throw new Error('Set `site` in astro.config.ts to generate llms.txt');

  const docs = await getDocs();
  const summaries = new Map(docs.map((entry) => [entry.id, summaryOf(entry.body)]));
  const base = import.meta.env.BASE_URL;

  const sections = navGroups(docs).map((group) => {
    const items = group.items.map((item) => {
      const url = new URL(withBase(item.route, base), site).href;
      const summary = summaries.get(item.id);
      return `- [${item.title}](${url})${summary ? `: ${summary}` : ''}`;
    });
    return `## ${group.label}\n${items.join('\n')}`;
  });

  return new Response(
    `# Thoth\n\n> Private N-of-M attestation for Midnight.\n\n${sections.join('\n\n')}\n`,
    { headers: { 'content-type': 'text/plain; charset=utf-8' } },
  );
};
