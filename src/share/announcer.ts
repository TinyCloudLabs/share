/**
 * TC-1583. The screen-reader-only live region that speaks what the page is
 * waiting for ("Approve in the OpenKey window to revoke.") and how it ended.
 *
 * Its text is a statement about the present, so it never outlives it: every way
 * an approval ends (approved, refused, cancelled, timed out, screen replaced,
 * signed out) either replaces the text with the matching outcome or clears it.
 * Nothing may be left saying "Approve in the OpenKey window…" once the window
 * is gone, because a screen-reader user browsing the page would still find it.
 */

/** A live region is announced when its text changes after it exists, so the new text goes in a moment after the old is cleared. */
export const ANNOUNCE_DELAY_MS = 100;

export interface Announcer {
  readonly element: HTMLElement;
  /** Replaces whatever is there (also a statement still waiting to be spoken) with `text`. */
  say(text: string): void;
  /** Empties the region and drops a statement that was still waiting to be spoken. */
  clear(): void;
  /** Clears the region for good: later `say` calls change nothing (the screen it belonged to is gone). */
  close(): void;
}

export function createAnnouncer(doc: Document, className: string): Announcer {
  const element = doc.createElement("p");
  element.className = `sr-only ${className}`;
  element.setAttribute("role", "status");
  element.setAttribute("aria-live", "polite");
  const view = doc.defaultView ?? window;
  let pending: number | undefined;
  let closed = false;
  const cancel = (): void => { if (pending !== undefined) { view.clearTimeout(pending); pending = undefined; } };
  return {
    element,
    say: (text) => {
      if (closed) return;
      cancel();
      element.textContent = "";
      pending = view.setTimeout(() => { pending = undefined; element.textContent = text; }, ANNOUNCE_DELAY_MS);
    },
    clear: () => { cancel(); element.textContent = ""; },
    close: () => { closed = true; cancel(); element.textContent = ""; },
  };
}
