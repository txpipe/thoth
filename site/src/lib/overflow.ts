// Marks which edges of a horizontal scroller hide content, so CSS can fade them,
// and makes the scroller keyboard-focusable only while it actually overflows.

/**
 * Keep `data-overflow` on `marked` set to the scroller's hidden edges:
 * `start`, `end`, both, or absent when everything fits.
 *
 * @param label Accessible region label applied while the container overflows horizontally.
 */
export function watchOverflow(
  scroller: HTMLElement,
  marked: HTMLElement = scroller,
  label?: string,
): void {
  const update = () => {
    const hidden = scroller.scrollWidth - scroller.clientWidth;
    const edges: string[] = [];
    if (scroller.scrollLeft > 1) edges.push('start');
    if (scroller.scrollLeft < hidden - 1) edges.push('end');
    if (edges.length > 0) marked.dataset.overflow = edges.join(' ');
    else delete marked.dataset.overflow;

    // Keyboard users need focusability to scroll clipped content with arrow keys,
    // without adding empty tab stops when the container already fits.
    if (hidden > 1) {
      scroller.tabIndex = 0;
      if (label) {
        scroller.setAttribute('role', 'region');
        scroller.setAttribute('aria-label', label);
      }
    } else {
      scroller.removeAttribute('tabindex');
      if (label) {
        scroller.removeAttribute('role');
        scroller.removeAttribute('aria-label');
      }
    }
  };
  scroller.addEventListener('scroll', update, { passive: true });
  new ResizeObserver(update).observe(scroller);
  update();
}
