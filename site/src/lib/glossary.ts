// Term anchors for the glossary: each bold term in CONTEXT.md gets its own id,
// so a link that names a term lands on the term, not on its section heading.

import { slug } from 'github-slugger';
import type { fromMarkdown } from 'mdast-util-from-markdown';
import { toString as nodeToString } from 'mdast-util-to-string';
import { visit } from 'unist-util-visit';

/** The repo path of the glossary. */
export const GLOSSARY = 'CONTEXT.md';

type MarkdownTree = ReturnType<typeof fromMarkdown>;
type Paragraph = Extract<MarkdownTree['children'][number], { type: 'paragraph' }>;

export interface Term {
  /** The term's name as the glossary writes it. */
  name: string;
  /** The id the term's paragraph carries on the site. */
  id: string;
  paragraph: Paragraph;
}

/**
 * The lookup key for a term or a link's text: case, spacing and code ticks
 * drop, so `TrustedSet`, `trusted set` and `Trusted set` all match.
 */
export function termKey(text: string): string {
  return text.toLowerCase().replace(/[^a-z0-9]/g, '');
}

/**
 * The glossary's terms by lookup key. A term is a paragraph that opens with a
 * bold name followed by a colon. Its id is the name's slug, or `term-` plus the
 * slug when a heading already uses that slug.
 */
export function termsOf(tree: MarkdownTree, headingSlugs: ReadonlySet<string>): Map<string, Term> {
  const terms = new Map<string, Term>();
  visit(tree, 'paragraph', (paragraph) => {
    const [name, rest] = paragraph.children;
    if (name?.type !== 'strong' || rest?.type !== 'text' || !rest.value.startsWith(':')) return;
    const text = nodeToString(name);
    const base = slug(text);
    const id = headingSlugs.has(base) ? `term-${base}` : base;
    terms.set(termKey(text), { name: text, id, paragraph });
  });
  return terms;
}

/** The term a link's text names, allowing a plural (`attestors` names Attestor). */
export function findTerm(terms: ReadonlyMap<string, Term>, text: string): Term | undefined {
  const key = termKey(text);
  const singulars = [key, key.replace(/ies$/, 'y'), key.replace(/es$/, ''), key.replace(/s$/, '')];
  for (const candidate of singulars) {
    const term = terms.get(candidate);
    if (term) return term;
  }
  return undefined;
}
