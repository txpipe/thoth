// Sets a doc's H1 on the site where the repo's own opening doesn't fit the page.

import path from 'node:path';
import type { Root } from 'mdast';
import { headingFor } from './docs';

export interface Options {
  repoRoot: string;
}

// The README opens with a centred GitHub banner (logo, tagline, badges) instead
// of an H1. The site header already carries the logo, so the site drops the
// banner and uses its tagline as the H1.
const BANNER = /^<div align="center">/;
const TAGLINE = /<strong>([^<]+)<\/strong>/;

export function retitle(options: Options) {
  return (tree: Root, file: { path?: string }): void => {
    if (!file.path) return;
    const [first] = tree.children;
    if (first?.type === 'html' && BANNER.test(first.value)) {
      const tagline = TAGLINE.exec(first.value)?.[1];
      if (!tagline) throw new Error(`${file.path}: the opening banner has no <strong> tagline`);
      tree.children[0] = {
        type: 'heading',
        depth: 1,
        children: [{ type: 'text', value: tagline }],
      };
      return;
    }
    const id = path.relative(options.repoRoot, file.path).split(path.sep).join('/');
    const heading = headingFor(id.replace(/\.md$/, ''));
    if (!heading) return;
    const h1 = tree.children.find((node) => node.type === 'heading' && node.depth === 1);
    if (h1?.type === 'heading') h1.children = [{ type: 'text', value: heading }];
  };
}
