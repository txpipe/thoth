// Marks code for search and line breaking. Code blocks stay out of the search
// index, so results quote prose rather than code; a short inline code span,
// such as a package name, doesn't break at its hyphens.

import type { Element, ElementContent, Root } from 'hast';
import { visit } from 'unist-util-visit';

function textOf(node: ElementContent): string {
  if (node.type === 'text') return node.value;
  return node.type === 'element' ? node.children.map(textOf).join('') : '';
}

// Longer spans are hashes or paths that must be able to wrap on a phone: at
// this length a span still fits the narrowest screen's column.
const SHORT = 24;

/** Rehype plugin that keeps code blocks out of Pagefind and short inline code on one line. */
export function codeHints() {
  return (tree: Root): void => {
    visit(tree, 'element', (node: Element, _index, parent) => {
      if (node.tagName === 'pre') {
        node.properties = { ...node.properties, dataPagefindIgnore: '' };
        return;
      }
      if (node.tagName !== 'code' || (parent?.type === 'element' && parent.tagName === 'pre')) {
        return;
      }
      const text = textOf(node);
      if (text.length <= SHORT && !/\s/.test(text)) {
        const classes = Array.isArray(node.properties?.className) ? node.properties.className : [];
        node.properties = { ...node.properties, className: [...classes, 'nowrap'] };
      }
    });
  };
}
