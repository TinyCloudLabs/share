// Recipients typed at the end of the landing headline. The longest sets the headline's fit; see `.share-target` in landing.css.
export const SHARE_TARGETS: readonly string[] = [
  "a person",
  "your family",
  "your friends",
  "your team",
  "your group chat",
  "your community",
  "your club",
  "your company",
  "an email address",
];

export const TYPE_MS = 60;
export const DELETE_MS = 30;
export const HOLD_MS = 1100;

/**
 * Types the phrases into `wrapper` (`.share-target` with `.share-target-text`) one character at a
 * time behind a blinking cursor, holds each for HOLD_MS, deletes it, and types the next, looping
 * through the list. Hover or focus inside the wrapper pauses typing. Returns a cancel function that
 * clears the timer and listeners.
 *
 * Reduced motion, or a missing text node: nothing changes, and the first phrase rendered in the
 * static HTML stays.
 */
export function startShareTargetRotation(wrapper: HTMLElement, win: Window = window): () => void {
  const text = wrapper.querySelector<HTMLElement>(".share-target-text");
  if (win.matchMedia("(prefers-reduced-motion: reduce)").matches || !text) {
    return () => {};
  }

  const cursor = win.document.createElement("span");
  cursor.className = "share-target-cursor";
  cursor.setAttribute("aria-hidden", "true");
  cursor.textContent = "|";
  text.after(cursor);
  text.textContent = "";

  let index = 0;
  let length = 0;
  let deleting = false;
  let paused = false;
  let timer: number | undefined;

  const schedule = (ms: number): void => {
    timer = win.setTimeout(step, ms);
  };

  const step = (): void => {
    if (paused) return schedule(TYPE_MS);
    const phrase = SHARE_TARGETS[index] ?? "";
    if (!deleting && length < phrase.length) {
      length += 1;
      text.textContent = phrase.slice(0, length);
      schedule(length < phrase.length ? TYPE_MS : HOLD_MS);
      return;
    }
    deleting = true;
    length -= 1;
    text.textContent = phrase.slice(0, length);
    if (length > 0) return schedule(DELETE_MS);
    deleting = false;
    index = (index + 1) % SHARE_TARGETS.length;
    schedule(TYPE_MS);
  };

  const cancel = (): void => {
    win.clearTimeout(timer);
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
  schedule(TYPE_MS);

  return cancel;
}
