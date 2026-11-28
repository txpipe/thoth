// Sets a doc's H1 on the site where the repo's own opening doesn't fit the page.

import path from 'node:path';
import type { PhrasingContent, Root } from 'mdast';
import { headingFor } from './docs';

export interface Options {
  repoRoot: string;
}

// The README opens with a centred GitHub banner (logo, tagline, badges) instead
// of an H1. The site header already carries the logo, so the site drops the
// banner and uses its tagline as the H1.
const BANNER = /^<div align="center">/;
const TAGLINE = /<strong>([^<]+)<\/strong>/;

// A hyphenated word in a display heading, such as "N-of-M", would break at its
// hyphens on a phone; each one renders as a span that doesn't wrap.
function unbroken(text: string): PhrasingContent[] {
  return text
    .split(/(\S+-\S+)/)
    .filter(Boolean)
    .map((part) =>
      part.includes('-') && !/\s/.test(part)
        ? {
            type: 'emphasis',
            data: { hName: 'span', hProperties: { className: ['nowrap'] } },
            children: [{ type: 'text', value: part }],
          }
        : { type: 'text', value: part },
    );
}

// A package's title, such as "@txpipe/thoth-zk-tls dApp integration", is wider
// than the column at display size: it may break after the npm scope, and never
// inside the package's name.
const SCOPED = /^(@[\w-]+\/)(\S+)([\s\S]*)$/;

function scoped(text: string): PhrasingContent[] | undefined {
  const match = SCOPED.exec(text);
  if (!match) return undefined;
  const [, scope = '', name = '', rest = ''] = match;
  return [
    { type: 'text', value: scope },
    { type: 'emphasis', data: { hName: 'wbr' }, children: [] },
    {
      type: 'emphasis',
      data: { hName: 'span', hProperties: { className: ['nowrap'] } },
      children: [{ type: 'text', value: name }],
    },
    ...(rest ? [{ type: 'text', value: rest } as const] : []),
  ];
}

export function retitle(options: Options) {
  return (tree: Root, file: { path?: string }): void => {
    if (!file.path) return;
    const [first] = tree.children;
    if (first?.type === 'html' && BANNER.test(first.value)) {
      const tagline = TAGLINE.exec(first.value)?.[1];
      if (!tagline) throw new Error(`${file.path}: the opening banner has no <strong> tagline`);
      tree.children[0] = { type: 'heading', depth: 1, children: unbroken(tagline) };
      return;
    }
    const id = path.relative(options.repoRoot, file.path).split(path.sep).join('/');
    const heading = headingFor(id.replace(/\.md$/, ''));
    const h1 = tree.children.find((node) => node.type === 'heading' && node.depth === 1);
    if (h1?.type !== 'heading') return;
    if (heading) {
      h1.children = [{ type: 'text', value: heading }];
      return;
    }
    const [only, ...others] = h1.children;
    const parts = only?.type === 'text' && others.length === 0 ? scoped(only.value) : undefined;
    if (parts) h1.children = parts;
  };
}
