// Recipient kinds that work end to end in Share today. A phrase is added only when its kind is live; see README "Landing page: recipient kinds".
export const SHARE_TARGETS: readonly string[] = ["a person", "an email address", "your team's domain"];

export const ROTATE_EVERY_MS = 2500;
export const ROTATE_STOP_AFTER_MS = 15000;

/**
 * Rotates the phrase inside `wrapper` (`.share-target`, containing `.share-target-text`).
 * Returns a stop function. With reduced motion, nothing changes and no timer is created.
 * Auto-rotation stops after ROTATE_STOP_AFTER_MS and settles on the first phrase. Hover or
 * focus inside the wrapper pauses the rotation; paused ticks still count toward the stop.
 */
export function startShareTargetRotation(wrapper: HTMLElement, win: Window = window): () => void {
  if (win.matchMedia("(prefers-reduced-motion: reduce)").matches) return () => {};

  const text = wrapper.querySelector<HTMLElement>(".share-target-text");
  if (!text) return () => {};

  wrapper.dataset.longest = SHARE_TARGETS.reduce((a, b) => (b.length > a.length ? b : a), "");

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

  const timer = win.setInterval(() => {
    elapsed += ROTATE_EVERY_MS;
    if (!paused) show((index + 1) % SHARE_TARGETS.length);
    if (elapsed >= ROTATE_STOP_AFTER_MS) {
      stop();
      if (index !== 0) show(0);
    }
  }, ROTATE_EVERY_MS);

  const stop = (): void => {
    win.clearInterval(timer);
    wrapper.removeEventListener("pointerenter", pause);
    wrapper.removeEventListener("pointerleave", resume);
    wrapper.removeEventListener("focusin", pause);
    wrapper.removeEventListener("focusout", resume);
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

  return stop;
}
