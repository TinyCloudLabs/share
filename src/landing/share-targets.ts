// Recipient kinds that work end to end in Share today. A phrase is added only when its kind is live; see README "Landing page: recipient kinds".
export const SHARE_TARGETS: readonly string[] = ["a person", "an email address", "your team's domain"];

export const ROTATE_EVERY_MS = 2500;
export const ROTATE_STOP_AFTER_MS = 15000;

/** Longest phrase by character count. brand.ts renders it into `data-longest` on `.share-target`. */
export function longestShareTarget(): string {
  return SHARE_TARGETS.reduce((a, b) => (b.length > a.length ? b : a), "");
}

/**
 * Rotates the phrase inside `wrapper` (`.share-target` with `.share-target-text`). The longest
 * phrase's width is reserved by the CSS `.share-target::after` rule, fed by `data-longest` rendered
 * statically from `longestShareTarget()`. Returns a cancel function that clears the timer and listeners.
 *
 * Reduced motion, or a missing text node: no timer is created, and CSS drops the reservation under
 * reduced motion, so the line is as wide as the first phrase from first paint. Otherwise the
 * reservation holds the width during rotation. After ROTATE_STOP_AFTER_MS the rotation settles on
 * the first phrase and the reserved width collapses to it in one transition. Hover or focus inside
 * the wrapper pauses rotation; paused ticks still count toward the stop.
 */
export function startShareTargetRotation(wrapper: HTMLElement, win: Window = window): () => void {
  const text = wrapper.querySelector<HTMLElement>(".share-target-text");
  if (win.matchMedia("(prefers-reduced-motion: reduce)").matches || !text) {
    return () => {};
  }

  let index = 0;
  let elapsed = 0;
  let paused = false;

  const show = (next: number): void => {
    index = next;
    text.textContent = SHARE_TARGETS[next] ?? "";
    text.classList.remove("is-entering");
    void text.offsetWidth;
    text.classList.add("is-entering");
  };

  const collapse = (): void => {
    const from = wrapper.getBoundingClientRect().width;
    wrapper.style.width = `${from}px`;
    wrapper.classList.add("is-settled");
    const to = text.getBoundingClientRect().width;
    if (to === from) {
      wrapper.style.removeProperty("width");
      return;
    }
    void wrapper.offsetWidth;
    wrapper.style.width = `${to}px`;
    wrapper.addEventListener("transitionend", () => wrapper.style.removeProperty("width"), { once: true });
  };

  const timer = win.setInterval(() => {
    elapsed += ROTATE_EVERY_MS;
    if (!paused) show((index + 1) % SHARE_TARGETS.length);
    if (elapsed >= ROTATE_STOP_AFTER_MS) settle();
  }, ROTATE_EVERY_MS);

  const cancel = (): void => {
    win.clearInterval(timer);
    wrapper.removeEventListener("pointerenter", pause);
    wrapper.removeEventListener("pointerleave", resume);
    wrapper.removeEventListener("focusin", pause);
    wrapper.removeEventListener("focusout", resume);
  };
  const settle = (): void => {
    cancel();
    if (index !== 0) show(0);
    collapse();
  };
  const pause = (): void => {
    paused = true;
  };
  const resume = (): void => {
    paused = false;
  };

  wrapper.addEventListener("pointerenter", pause);
  wrapper.addEventListener("pointerleave", resume);
  wrapper.addEventListener("focusin", pause);
  wrapper.addEventListener("focusout", resume);

  return cancel;
}
