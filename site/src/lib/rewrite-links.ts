// Rewrites repo links in the published docs to site routes and checks them.
// Links into the glossary land on the term they name, and a link whose text is
// the target's file path shows the target's site title instead. A link to the
// site itself, such as the README's "Docs site" entry, is dropped.

import { existsSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import GithubSlugger from 'github-slugger';
import { fromMarkdown } from 'mdast-util-from-markdown';
import { toString as nodeToString } from 'mdast-util-to-string';
import { visit } from 'unist-util-visit';
import { isPublished, REPO_URL, routeFor, titleFor, withBase } from './docs';
import { findTerm, GLOSSARY, type Term, termsOf } from './glossary';

const BLOB = `${REPO_URL}/blob/main/`;

export interface Options {
  repoRoot: string;
  base: string;
  /** The published site's root URL, with its base and no trailing slash. */
  siteUrl: string;
}

type MarkdownTree = ReturnType<typeof fromMarkdown>;
type Paragraph = Extract<MarkdownTree['children'][number], { type: 'paragraph' }>;
type Link = Paragraph['children'][number] & { type: 'link' };
type Parent = { type: string; children: unknown[] };

// Words a description can drop and still say the same as a title.
const FILLER = new Set(['a', 'an', 'and', 'how', 'its', 'of', 'the', 'to']);

function contentWords(text: string): string[] {
  return text
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter((word) => word && !FILLER.has(word));
}

/**
 * Whether a description only restates a title: each of its words starts a
 * title word or is started by one, so "how to add an attestor kind" restates
 * "Adding an attestor kind" and "the glossary" restates "Glossary".
 */
function restates(description: string, title: string): boolean {
  const words = contentWords(description);
  const titleWords = contentWords(title);
  return (
    words.length > 0 &&
    words.every((word) =>
      titleWords.some((other) => other.startsWith(word) || word.startsWith(other)),
    )
  );
}

interface Doc {
  anchors: Set<string>;
  terms: Map<string, Term>;
  title: string;
}

function headingSlugs(tree: MarkdownTree): Set<string> {
  const slugger = new GithubSlugger();
  const slugs = new Set<string>();
  visit(tree, 'heading', (heading) => {
    slugs.add(slugger.slug(nodeToString(heading)));
  });
  return slugs;
}

function splitFragment(url: string): [string, string] {
  const index = url.indexOf('#');
  return index < 0 ? [url, ''] : [url.slice(0, index), url.slice(index + 1)];
}

function toPosix(value: string): string {
  return value.split(path.sep).join('/');
}

export function rewriteLinks(options: Options) {
  const cache = new Map<string, Doc>();

  function docFor(repoPath: string): Doc {
    const cached = cache.get(repoPath);
    if (cached) return cached;
    const file = path.join(options.repoRoot, ...repoPath.split('/'));
    const markdown = readFileSync(file, 'utf8');
    const tree = fromMarkdown(markdown);
    const anchors = headingSlugs(tree);
    const terms = repoPath === GLOSSARY ? termsOf(tree, anchors) : new Map<string, Term>();
    for (const term of terms.values()) anchors.add(term.id);
    const doc = { anchors, terms, title: titleFor(repoPath.replace(/\.md$/, ''), markdown) };
    cache.set(repoPath, doc);
    return doc;
  }

  function checkAnchor(repoPath: string, fragment: string, source: string, url: string): void {
    if (!fragment) return;
    if (!docFor(repoPath).anchors.has(fragment)) {
      throw new Error(`${source}: ${url} points at a missing anchor in ${repoPath}`);
    }
  }

  return (tree: MarkdownTree, file: { path?: string }): void => {
    if (!file.path) return;
    const source = toPosix(path.relative(options.repoRoot, file.path));
    if (source.startsWith('../')) {
      throw new Error(`rewriteLinks: ${file.path} is outside the repo`);
    }

    // Point a link at a published doc's route. A glossary link whose text names
    // a term goes to that term; a link whose text is the file path reads as the
    // doc's site title, the name the nav uses. In a "path: description" list
    // entry, a description that only restates that title drops.
    function toSite(
      node: { url: string },
      repoPath: string,
      fragment: string,
      url: string,
      parent: Parent | undefined,
      index: number | undefined,
    ): void {
      const target = docFor(repoPath);
      let anchor = fragment;
      if ('children' in node) {
        const link = node as Link;
        const text = nodeToString(link);
        const term = repoPath === GLOSSARY ? findTerm(target.terms, text) : undefined;
        if (term) anchor = term.id;
        const [pathPart = ''] = splitFragment(url.startsWith(BLOB) ? url.slice(BLOB.length) : url);
        const shown = text.trim();
        if (shown === repoPath || shown === pathPart || shown === path.posix.basename(repoPath)) {
          link.children = [
            target.title.startsWith('@')
              ? { type: 'inlineCode', value: target.title }
              : { type: 'text', value: target.title },
          ];
          const rest = index === undefined ? undefined : parent?.children[index + 1];
          const isLast = index !== undefined && parent?.children.length === index + 2;
          if (
            isLast &&
            rest &&
            typeof rest === 'object' &&
            'type' in rest &&
            rest.type === 'text' &&
            'value' in rest &&
            typeof rest.value === 'string' &&
            rest.value.startsWith(':') &&
            restates(rest.value.slice(1), target.title)
          ) {
            parent?.children.splice(index + 1, 1);
          }
        }
      }
      node.url = withBase(routeFor(repoPath), options.base) + (anchor ? `#${anchor}` : '');
    }

    // Give every glossary term the id that links to it use.
    if (source === GLOSSARY) {
      for (const term of termsOf(tree, headingSlugs(tree)).values()) {
        term.paragraph.data = {
          ...term.paragraph.data,
          hProperties: { id: term.id, className: ['glossary-term'] },
        };
      }
    }

    function rewrite(
      node: { url: string },
      index: number | undefined,
      parent: Parent | undefined,
    ): void {
      const url = node.url;
      if (!url || url.startsWith('/') || url.startsWith('//')) return;

      if (url.startsWith('#')) {
        checkAnchor(source, url.slice(1), source, url);
        return;
      }

      // Published docs keep resolving on the site; unpublished GitHub links stay.
      if (url.startsWith(BLOB)) {
        const [repoPath, fragment] = splitFragment(url.slice(BLOB.length));
        if (!repoPath.endsWith('.md') || !isPublished(repoPath)) return;
        const absolute = path.join(options.repoRoot, ...repoPath.split('/'));
        if (!existsSync(absolute)) {
          throw new Error(`${source}: ${url} does not resolve`);
        }
        checkAnchor(repoPath, fragment, source, url);
        toSite(node, repoPath, fragment, url, parent, index);
        return;
      }

      if (/^[a-z][a-z0-9+.-]*:/i.test(url)) return;

      const [pathPart, fragment] = splitFragment(url);
      const bare = pathPart.split('?')[0] ?? '';
      if (!bare) return;
      const target = path.posix.normalize(path.posix.join(path.posix.dirname(source), bare));
      if (target.startsWith('../')) {
        throw new Error(`${source}: ${url} leaves the repo`);
      }
      const absolute = path.join(options.repoRoot, ...target.split('/'));
      if (!existsSync(absolute)) {
        throw new Error(`${source}: ${url} does not resolve`);
      }

      const isDirectory = statSync(absolute).isDirectory();
      if (!isDirectory && isPublished(target)) {
        checkAnchor(target, fragment, source, url);
        toSite(node, target, fragment, url, parent, index);
        return;
      }
      node.url = `${REPO_URL}/${isDirectory ? 'tree' : 'blob'}/main/${target}${
        fragment ? `#${fragment}` : ''
      }`;
    }

    // A list entry that only links the site to itself has nothing to offer on it.
    visit(tree, 'listItem', (item, index, list) => {
      const [paragraph, ...others] = item.children;
      const [first] = paragraph?.type === 'paragraph' ? paragraph.children : [];
      const self = first?.type === 'link' && first.url.replace(/\/$/, '') === options.siteUrl;
      if (!self || others.length > 0 || !list || index === undefined) return;
      list.children.splice(index, 1);
      return index;
    });

    visit(tree, 'link', (node, index, parent) => rewrite(node, index, parent));
    visit(tree, 'definition', (node, index, parent) => rewrite(node, index, parent));
  };
}
