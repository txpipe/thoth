// Marks prose links that leave the docs site: an arrow the last word can't wrap
// away from, and the word "external" for screen readers.

import type { Element, ElementContent, Root } from 'hast';
import { visit } from 'unist-util-visit';

export interface Options {
  /** The site's own origin and base, such as `https://txpipe.github.io/thoth`. */
  siteUrl: string;
}

const icon = (): Element => ({
  type: 'element',
  tagName: 'span',
  properties: { className: ['external-icon'], ariaHidden: 'true' },
  children: [],
});

/** Rehype plugin that marks `http(s)` links outside the site as external. */
export function externalLinks(options: Options) {
  return (tree: Root): void => {
    visit(tree, 'element', (node) => {
      if (node.tagName !== 'a') return;
      const href = String(node.properties?.href ?? '');
      if (!/^https?:\/\//.test(href) || href.startsWith(options.siteUrl)) return;
      const last = node.children.at(-1);
      if (!last) return;

      // Keep the arrow on the line of the link's last word.
      const tail: Element = {
        type: 'element',
        tagName: 'span',
        properties: { className: ['external-tail'] },
        children: [],
      };
      if (last.type === 'text') {
        const match = /^([\s\S]*?)(\S+\s*)$/.exec(last.value);
        if (!match) return;
        const [, head = '', word = ''] = match;
        node.children.splice(-1, 1, ...(head ? [{ type: 'text', value: head } as const] : []));
        tail.children = [{ type: 'text', value: word.trimEnd() }, icon()];
      } else {
        // The tail's nowrap only governs the break between the code and the
        // arrow; the code itself still wraps inside (see .external-tail > code).
        node.children.pop();
        tail.children = [last as ElementContent, icon()];
      }
      node.children.push(tail, {
        type: 'element',
        tagName: 'span',
        // Read aloud, but kept out of search excerpts.
        properties: { className: ['visually-hidden'], dataPagefindIgnore: '' },
        children: [{ type: 'text', value: ' (external)' }],
      });
      const classes = node.properties.className;
      node.properties.className = [...(Array.isArray(classes) ? classes : []), 'external'];
    });
  };
}
