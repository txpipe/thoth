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

/** Rehype plugin that appends a `#` permalink anchor inside each `h2` and `h3` with an id. */
export function headingLinks() {
  return (tree: HastNode): void => {
    visit(tree, (node) => {
      if (node.type !== 'element') return;
      const heading = node as HastElement;
      if (heading.tagName !== 'h2' && heading.tagName !== 'h3') return;
      const id = heading.properties?.id;
      if (typeof id !== 'string' || !id) return;

      // Keep the anchor empty in HTML and draw `#` via CSS `::before` so Astro's
      // heading-collection pass does not append `#` to table-of-contents titles.
      heading.children.push({
        type: 'element',
        tagName: 'a',
        properties: {
          className: ['heading-anchor'],
          href: `#${id}`,
          // A pointer convenience: the table of contents already links every
          // section, so the anchor stays out of the tab order. It is hidden
          // from screen readers too, or its name would be read as part of
          // every heading.
          tabIndex: -1,
          ariaHidden: 'true',
        },
        children: [],
      });
    });
  };
}
