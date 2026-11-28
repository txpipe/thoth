// Typo-tolerant word matching, shared by search's suggestion and the 404 page's guess.

/** The lowercase words of a text: runs of ASCII letters and digits. */
export function wordsOf(text: string): string[] {
  return text
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter(Boolean);
}

/**
 * Edit distance that counts a swap of two neighbours as one edit, so "desing"
 * is one edit from "design".
 */
export function distance(a: string, b: string): number {
  const rows = Array.from({ length: a.length + 1 }, (_, i) =>
    Array.from({ length: b.length + 1 }, (_, j) => (i === 0 ? j : j === 0 ? i : 0)),
  );
  for (let i = 1; i <= a.length; i += 1) {
    for (let j = 1; j <= b.length; j += 1) {
      const row = rows[i] ?? [];
      const above = rows[i - 1] ?? [];
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      row[j] = Math.min((above[j] ?? 0) + 1, (row[j - 1] ?? 0) + 1, (above[j - 1] ?? 0) + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        row[j] = Math.min(row[j] ?? 0, (rows[i - 2]?.[j - 2] ?? 0) + 1);
      }
    }
  }
  return rows[a.length]?.[b.length] ?? 0;
}

/**
 * How many edits a mistyped word may be from the word it means: two for a long
 * word, one for a short one, none under four letters, where any edit changes
 * the word.
 */
export function tolerance(word: string): number {
  if (word.length >= 7) return 2;
  return word.length >= 4 ? 1 : 0;
}

/**
 * The query with each word that isn't in `vocabulary` replaced by the closest
 * word that is, within its tolerance. Empty when no word changes.
 */
export function correct(query: string, vocabulary: readonly string[]): string {
  let changed = false;
  const words = wordsOf(query).map((word) => {
    if (vocabulary.includes(word)) return word;
    let best = word;
    let fewest = tolerance(word) + 1;
    for (const candidate of vocabulary) {
      const edits = distance(word, candidate);
      if (edits < fewest) {
        best = candidate;
        fewest = edits;
      }
    }
    if (best !== word) changed = true;
    return best;
  });
  return changed ? words.join(' ') : '';
}
