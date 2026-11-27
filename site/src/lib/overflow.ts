// Marks which edges of a horizontal scroller hide content, so CSS can fade them.

/**
 * Keep `data-overflow` on `marked` set to the scroller's hidden edges:
 * `start`, `end`, both, or absent when everything fits.
 */
export function watchOverflow(scroller: HTMLElement, marked: HTMLElement = scroller): void {
  const update = () => {
    const hidden = scroller.scrollWidth - scroller.clientWidth;
    const edges: string[] = [];
    if (scroller.scrollLeft > 1) edges.push('start');
    if (scroller.scrollLeft < hidden - 1) edges.push('end');
    if (edges.length > 0) marked.dataset.overflow = edges.join(' ');
    else delete marked.dataset.overflow;
  };
  scroller.addEventListener('scroll', update, { passive: true });
  new ResizeObserver(update).observe(scroller);
  update();
}
