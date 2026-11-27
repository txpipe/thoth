// Rewrites repo links in the published docs to site routes and checks them.
// Links into the glossary land on the term they name, and a link whose text is
// the target's file path shows the target's site title instead.

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
}

type MarkdownTree = ReturnType<typeof fromMarkdown>;
type Link = Extract<MarkdownTree['children'][number], { type: 'paragraph' }>['children'][number] & {
  type: 'link';
};

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
    // doc's site title, the name the nav uses.
    function toSite(node: { url: string }, repoPath: string, fragment: string, url: string): void {
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

    function rewrite(node: { url: string }): void {
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
        toSite(node, repoPath, fragment, url);
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
        toSite(node, target, fragment, url);
        return;
      }
      node.url = `${REPO_URL}/${isDirectory ? 'tree' : 'blob'}/main/${target}${
        fragment ? `#${fragment}` : ''
      }`;
    }

    visit(tree, 'link', rewrite);
    visit(tree, 'definition', rewrite);
  };
}
