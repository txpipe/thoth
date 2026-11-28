// Marks prose links that leave the docs site: an arrow the last word can't wrap
// away from, and the word "external" for screen readers.

import type { Element, ElementContent, Root } from 'hast';
import { visit } from 'unist-util-visit';

export interface Options {
  /** The site's own origin and base, such as `https://txpipe.github.io/thoth`. */
  siteUrl: string;
}

// The longest last word that stays whole next to its arrow.
const LONG = 20;

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
        const [, lead = '', end = ''] = match;
        // A long last word, such as a path, would overflow a phone if it
        // couldn't wrap: only its final segment stays with the arrow.
        const word = end.trimEnd();
        const cut = word.length > LONG ? word.slice(0, -1).search(/[/.-][^/.-]*$/) + 1 : 0;
        const head = lead + word.slice(0, cut);
        node.children.splice(-1, 1, ...(head ? [{ type: 'text', value: head } as const] : []));
        tail.children = [{ type: 'text', value: word.slice(cut) }, icon()];
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
