// Appends a visible `#` permalink anchor to every h2 and h3 heading with an id.

import { visit } from 'unist-util-visit';

interface HastText {
  type: 'text';
  value: string;
}

interface HastElement {
  type: 'element';
  tagName: string;
  properties?: Record<string, unknown>;
  children: HastNode[];
}

type HastNode = HastElement | HastText | { type: string; children?: HastNode[] };

function textOf(node: HastNode): string {
  if (node.type === 'text' && 'value' in node) return node.value;
  if ('children' in node && Array.isArray(node.children)) {
    return node.children.map(textOf).join('');
  }
  return '';
}

/** Rehype plugin that appends a `#` permalink anchor inside each `h2` and `h3` with an id. */
export function headingLinks() {
  return (tree: HastNode): void => {
    visit(tree, (node) => {
      if (node.type !== 'element') return;
      const heading = node as HastElement;
      if (heading.tagName !== 'h2' && heading.tagName !== 'h3') return;
      const id = heading.properties?.id;
      if (typeof id !== 'string' || !id) return;

      const label = textOf(heading).trim();
      // Keep the anchor empty in HTML and draw `#` via CSS `::before` so Astro's
      // heading-collection pass does not append `#` to table-of-contents titles.
      heading.children.push({
        type: 'element',
        tagName: 'a',
        properties: {
          className: ['heading-anchor'],
          href: `#${id}`,
          ariaLabel: label ? `Link to ${label}` : 'Link to section',
        },
        children: [],
      });
    });
  };
}
