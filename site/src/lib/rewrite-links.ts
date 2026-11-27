// Rewrites repo links in the published docs to site routes and checks them.

import { existsSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import GithubSlugger from 'github-slugger';
import { fromMarkdown } from 'mdast-util-from-markdown';
import { toString as nodeToString } from 'mdast-util-to-string';
import { visit } from 'unist-util-visit';
import { isPublished, REPO_URL, routeFor, withBase } from './docs';

const BLOB = `${REPO_URL}/blob/main/`;

export interface Options {
  repoRoot: string;
  base: string;
}

type MarkdownTree = ReturnType<typeof fromMarkdown>;

function splitFragment(url: string): [string, string] {
  const index = url.indexOf('#');
  return index < 0 ? [url, ''] : [url.slice(0, index), url.slice(index + 1)];
}

function toPosix(value: string): string {
  return value.split(path.sep).join('/');
}

export function rewriteLinks(options: Options) {
  const cache = new Map<string, Set<string>>();

  function anchorsFor(repoPath: string): Set<string> {
    const cached = cache.get(repoPath);
    if (cached) return cached;
    const file = path.join(options.repoRoot, ...repoPath.split('/'));
    const tree = fromMarkdown(readFileSync(file, 'utf8'));
    const slugger = new GithubSlugger();
    const anchors = new Set<string>();
    visit(tree, 'heading', (heading) => {
      anchors.add(slugger.slug(nodeToString(heading)));
    });
    cache.set(repoPath, anchors);
    return anchors;
  }

  function checkAnchor(repoPath: string, fragment: string, source: string, url: string): void {
    if (!fragment) return;
    if (!anchorsFor(repoPath).has(fragment)) {
      throw new Error(`${source}: ${url} points at a missing anchor in ${repoPath}`);
    }
  }

  return (tree: MarkdownTree, file: { path?: string }): void => {
    if (!file.path) return;
    const source = toPosix(path.relative(options.repoRoot, file.path));
    if (source.startsWith('../')) {
      throw new Error(`rewriteLinks: ${file.path} is outside the repo`);
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
        node.url = withBase(routeFor(repoPath), options.base) + (fragment ? `#${fragment}` : '');
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
        node.url = withBase(routeFor(target), options.base) + (fragment ? `#${fragment}` : '');
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
