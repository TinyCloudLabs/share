/**
 * Phrases that rotate under the hero headline. Each one completes "Share what your agent makes ...".
 * The list is the README "Landing page: recipient kinds" list, in the same order; a test keeps them
 * equal. It deliberately includes kinds that are not live yet (product decision, 22 Oct 2026).
 */
export const SHARE_TARGETS: readonly string[] = [
  "with a person",
  "with an email address",
  "with your team",
  "with your friends",
  "with your family",
  "with your group chat",
  "with everyone at your company",
  "with your clients",
  "with your classmates",
  "with your neighbours",
];

/** One phrase every 2.8 s; one full pass, then the rotation stops on the first phrase. */
export const ROTATE_EVERY_MS = 2800;
export const ROTATE_STOP_AFTER_MS = ROTATE_EVERY_MS * SHARE_TARGETS.length;

/** Longest phrase by character count. brand.ts renders it into `data-longest` on `.share-target`. */
export function longestShareTarget(): string {
  return SHARE_TARGETS.reduce((a, b) => (b.length > a.length ? b : a), "");
}

/**
 * Rotates the phrase inside `wrapper` (`.share-target` holding `.share-target-text`). The longest
 * phrase is rendered into the CSS `.share-target::after` rule from `data-longest`, in the same grid
 * cell as the visible phrase, so the line keeps the height of the longest phrase at every viewport
 * width and nothing below it moves. Returns a cancel function that clears the timer and listeners.
 *
 * Reduced motion, or a missing text node: no timer is created and the first phrase stays.
 * After one full pass the rotation stops on the first phrase. Hover or focus inside the wrapper
 * pauses rotation; paused ticks still count toward the stop.
 */
export function startShareTargetRotation(wrapper: HTMLElement, win: Window = window): () => void {
  const text = wrapper.querySelector<HTMLElement>(".share-target-text");
  const slot = text?.parentElement;
  if (win.matchMedia("(prefers-reduced-motion: reduce)").matches || !text || !slot) {
    return () => {};
  }

  let index = 0;
  let elapsed = 0;
  let paused = false;

  const show = (next: number): void => {
    index = next;
    text.textContent = SHARE_TARGETS[next] ?? "";
    slot.classList.remove("is-entering");
    void slot.offsetWidth;
    slot.classList.add("is-entering");
  };

  const timer = win.setInterval(() => {
    elapsed += ROTATE_EVERY_MS;
    if (elapsed >= ROTATE_STOP_AFTER_MS) {
      cancel();
      if (index !== 0) show(0);
      return;
    }
    if (!paused) show((index + 1) % SHARE_TARGETS.length);
  }, ROTATE_EVERY_MS);

  const pause = (): void => {
    paused = true;
  };
  const resume = (): void => {
    paused = false;
  };
  const cancel = (): void => {
    win.clearInterval(timer);
    wrapper.removeEventListener("pointerenter", pause);
    wrapper.removeEventListener("pointerleave", resume);
    wrapper.removeEventListener("focusin", pause);
    wrapper.removeEventListener("focusout", resume);
  };

  wrapper.addEventListener("pointerenter", pause);
  wrapper.addEventListener("pointerleave", resume);
  wrapper.addEventListener("focusin", pause);
  wrapper.addEventListener("focusout", resume);

  return cancel;
}
