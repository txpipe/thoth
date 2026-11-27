// Content collection queries shared by the pages, the nav and llms.txt.

import { type CollectionEntry, getCollection } from 'astro:content';
import {
  DOC_FILES,
  GROUP_ORDER,
  isPackageGuide,
  navGroup,
  navLabel,
  routeFor,
  titleFor,
} from './docs';

export type DocEntry = CollectionEntry<'docs'>;

export interface NavItem {
  id: string;
  route: string;
  /** The nav label: short, since the group and the nesting give context. */
  title: string;
  /** The doc's full site title, for places without that context (the pager). */
  pageTitle: string;
  /** A package guide, shown under its package's README. */
  nested: boolean;
  /** For a nested guide, its package's short name, which screen readers hear first. */
  parent?: string;
  /**
   * For a package README, the npm scope its label drops (`@txpipe/thoth-`). The
   * nav shows it dimmed, so the full package name matches the page's title.
   */
  scope?: string;
}

export interface NavGroup {
  label: string;
  items: NavItem[];
}

export interface PageNeighbors {
  prev?: NavItem;
  next?: NavItem;
}

/** The previous and next docs in nav order across groups. */
export function neighborsOf(groups: NavGroup[], currentId: string): PageNeighbors {
  const flat = groups.flatMap((group) => group.items);
  const index = flat.findIndex((item) => item.id === currentId);
  if (index < 0) return {};
  return {
    prev: flat[index - 1],
    next: flat[index + 1],
  };
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

    const repoPath = `${entry.id}.md`;
    const group = navGroup(repoPath);
    const items = groups.get(group) ?? [];
    const nested = isPackageGuide(repoPath);
    const short = navLabel(repoPath, label);
    const scope = !nested && label.endsWith(short) ? label.slice(0, -short.length) : '';
    items.push({
      id: entry.id,
      route: routeFor(repoPath),
      title: short,
      pageTitle: label,
      nested,
      parent: nested ? repoPath.split('/')[1] : undefined,
      scope: scope || undefined,
    });
    groups.set(group, items);
  }

  return GROUP_ORDER.filter((label) => groups.has(label)).map((label) => ({
    label,
    items: groups.get(label) ?? [],
  }));
}
