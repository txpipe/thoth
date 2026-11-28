// Wraps Markdown tables in a scroll container at build time so <table> keeps its native display.

import type { Element, Root } from 'hast';
import { visit } from 'unist-util-visit';

function hasClass(node: Element, name: string): boolean {
  const classes = node.properties?.className;
  if (Array.isArray(classes)) return classes.includes(name);
  return String(classes ?? '')
    .split(/\s+/)
    .includes(name);
}

/** Rehype plugin that wraps each `<table>` in `<div class="table-wrap">` for sideways scrolling. */
export function wrapTables() {
  return (tree: Root): void => {
    visit(tree, 'element', (node, index, parent) => {
      if (node.tagName !== 'table' || !parent || index === undefined) return;
      if (parent.type === 'element' && hasClass(parent, 'table-wrap')) return;
      const wrapper: Element = {
        type: 'element',
        tagName: 'div',
        properties: { className: ['table-wrap'] },
        children: [node],
      };
      parent.children[index] = wrapper;
    });
  };
}
