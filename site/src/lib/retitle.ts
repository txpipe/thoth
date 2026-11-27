// Replaces a doc's H1 on the site where the repo H1 would mistitle the page.

import path from 'node:path';
import type { Root } from 'mdast';
import { headingFor } from './docs';

export interface Options {
  repoRoot: string;
}

export function retitle(options: Options) {
  return (tree: Root, file: { path?: string }): void => {
    if (!file.path) return;
    const id = path.relative(options.repoRoot, file.path).split(path.sep).join('/');
    const heading = headingFor(id.replace(/\.md$/, ''));
    if (!heading) return;
    const h1 = tree.children.find((node) => node.type === 'heading' && node.depth === 1);
    if (h1?.type === 'heading') h1.children = [{ type: 'text', value: heading }];
  };
}
