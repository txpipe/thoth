// Content collection queries shared by the pages, the nav and llms.txt.

import { type CollectionEntry, getCollection } from 'astro:content';
import { DOC_FILES, GROUP_ORDER, navGroup, routeFor, titleFor } from './docs';

export type DocEntry = CollectionEntry<'docs'>;

export interface NavItem {
  id: string;
  route: string;
  title: string;
}

export interface NavGroup {
  label: string;
  items: NavItem[];
}

// Throws instead of shipping a site with a silently missing allowlist entry.
export async function getDocs(): Promise<DocEntry[]> {
  const docs = await getCollection('docs');
  const missing = DOC_FILES.filter(
    (file) => !docs.some((entry) => entry.id === file.replace(/\.md$/, '')),
  );
  if (missing.length > 0) {
    throw new Error(`Allowlisted docs missing from the collection: ${missing.join(', ')}`);
  }
  return docs;
}

// Order is explicit docs first, then policy examples by title. A repeated H1
// gets its file stem appended so the nav never shows the same label twice.
export function navGroups(docs: DocEntry[]): NavGroup[] {
  const order = new Map(DOC_FILES.map((file, index) => [file.replace(/\.md$/, ''), index]));
  const sorted = [...docs].sort((a, b) => {
    const left = order.get(a.id) ?? Number.MAX_SAFE_INTEGER;
    const right = order.get(b.id) ?? Number.MAX_SAFE_INTEGER;
    return left === right
      ? titleFor(a.id, a.body).localeCompare(titleFor(b.id, b.body))
      : left - right;
  });

  const groups = new Map<string, NavItem[]>();
  const seen = new Set<string>();
  for (const entry of sorted) {
    const title = titleFor(entry.id, entry.body);
    const stem = entry.id.split('/').at(-1) ?? entry.id;
    const label = seen.has(title) ? `${title} (${stem})` : title;
    seen.add(title);

    const group = navGroup(`${entry.id}.md`);
    const items = groups.get(group) ?? [];
    items.push({ id: entry.id, route: routeFor(`${entry.id}.md`), title: label });
    groups.set(group, items);
  }

  return GROUP_ORDER.filter((label) => groups.has(label)).map((label) => ({
    label,
    items: groups.get(label) ?? [],
  }));
}
