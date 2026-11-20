// The publish allowlist and path-to-route mapping for the docs site.

export const POLICY_DIR = 'docs/policies';

// Adding a reader-facing doc is one entry here; a new file under POLICY_DIR is
// published by the loader's glob with no entry. Keep this list in nav order.
export const DOC_FILES = [
  'README.md',
  'CONTEXT.md',
  'docs/DESIGN.md',
  'docs/kind-author-guide.md',
  'packages/attestor/README.md',
  'packages/client/README.md',
  'packages/contracts/README.md',
  'packages/core/README.md',
  'packages/zk-tls/README.md',
  'packages/zk-tls/docs/attestor-guide.md',
  'packages/zk-tls/docs/dapp-integration.md',
];

const GROUP_RULES: ReadonlyArray<{ test: (repoPath: string) => boolean; label: string }> = [
  { test: (repoPath) => repoPath === 'README.md' || repoPath === 'CONTEXT.md', label: 'Overview' },
  { test: (repoPath) => repoPath.startsWith(`${POLICY_DIR}/`), label: 'Policy examples' },
  { test: (repoPath) => /^packages\/[^/]+\/README\.md$/.test(repoPath), label: 'Packages' },
  { test: (repoPath) => repoPath.startsWith('packages/zk-tls/docs/'), label: 'zkFetch guides' },
  { test: () => true, label: 'Guides' },
];

export const GROUP_ORDER = ['Overview', 'Guides', 'Policy examples', 'Packages', 'zkFetch guides'];

function isPolicy(repoPath: string): boolean {
  const name = repoPath.slice(POLICY_DIR.length + 1);
  return repoPath.startsWith(`${POLICY_DIR}/`) && name.endsWith('.md') && !name.includes('/');
}

/** Whether the site publishes a repo path. */
export function isPublished(repoPath: string): boolean {
  return DOC_FILES.includes(repoPath) || isPolicy(repoPath);
}

/** The site route for a published repo path, always with a leading and trailing slash. */
export function routeFor(repoPath: string): string {
  if (repoPath === 'README.md') return '/';
  const stem = repoPath.replace(/\/README\.md$/, '').replace(/\.md$/, '');
  return `/${stem}/`;
}

/** Prefix a site route with the Pages base path. */
export function withBase(route: string, base: string): string {
  return `${base.endsWith('/') ? base : `${base}/`}${route.replace(/^\//, '')}`;
}

/** The first H1 of a doc, used as its title. */
export function titleOf(markdown: string | undefined): string {
  const heading = (markdown ?? '').split('\n').find((line) => line.startsWith('# '));
  return heading ? heading.slice(2).trim() : 'Untitled';
}

// Site-only display names where the H1 is too generic or collides with another.
// The docs themselves stay untouched.
const TITLES: Record<string, string> = { README: 'Introduction', CONTEXT: 'Glossary' };

/** The title the site shows for a doc: an override by collection id, else its first H1. */
export function titleFor(id: string, markdown: string | undefined): string {
  return TITLES[id] ?? titleOf(markdown);
}

/** The first paragraph of a doc, used as its one-line note in llms.txt. */
export function summaryOf(markdown: string | undefined): string {
  const paragraph: string[] = [];
  for (const line of (markdown ?? '').split('\n')) {
    const text = line.trim();
    if (!text) {
      if (paragraph.length > 0) break;
      continue;
    }
    if (
      text.startsWith('#') ||
      text.startsWith('>') ||
      text.startsWith('```') ||
      text.startsWith('|') ||
      text.startsWith('- ') ||
      /^\d+\.\s/.test(text)
    ) {
      continue;
    }
    paragraph.push(text);
  }
  return paragraph
    .join(' ')
    .replace(/\[([^\]]+)\]\([^)]*\)/g, '$1')
    .replace(/[`*_]/g, '');
}

/** The nav group for a repo path. */
export function navGroup(repoPath: string): string {
  return GROUP_RULES.find((rule) => rule.test(repoPath))?.label ?? 'Guides';
}
