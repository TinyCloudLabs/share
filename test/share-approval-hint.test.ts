import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { APPROVAL_SLOW_AFTER_MS, APPROVAL_SLOW_COPY, type ApprovalHint, showApprovalHint } from "../src/share/approval-hint.ts";
import { OPENKEY_ORIGIN } from "../src/share/openkey-origin.ts";

const TIMEOUT_COPY = "The wait has gone on too long.";

let parent: HTMLElement;
let hint: ApprovalHint | undefined;

beforeEach(() => {
  vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "Date"], shouldAdvanceTime: true });
  parent = document.createElement("div");
  document.body.append(parent);
});
afterEach(() => {
  hint?.dispose();
  hint = undefined;
  document.body.replaceChildren();
  parent.remove();
  vi.useRealTimers();
});

/** Shows the hint and returns its help line. */
function show(): HTMLElement {
  hint = showApprovalHint(parent, { text: "Approve in the OpenKey window", lineClass: "sender-approval-line", timeoutCopy: TIMEOUT_COPY });
  return hint.element.querySelector<HTMLElement>(".sender-approval-more") as HTMLElement;
}

/**
 * The OpenKey window's child window. The SDK mounts its iframe in a closed shadow root, which `window.frames` does not
 * list, and jsdom gives such a frame no `contentWindow`. So the child is modelled by what the watcher reads: its `top`
 * is the page, not the child itself.
 */
function openKeyFrame(): Window {
  const child = {} as Window;
  Object.defineProperty(child, "top", { value: window });
  return child;
}

/** A top-level window, as the popup fallback opens: its `top` is itself. */
function popupWindow(): Window {
  const popup = {} as Window;
  Object.defineProperty(popup, "top", { value: popup });
  return popup;
}

/** Dispatches the message as the browser would, with `source` as the sending window. */
function postReady(source: Window, origin: string = OPENKEY_ORIGIN): void {
  const event = new MessageEvent("message", { origin, data: { type: "openkey:ready" } });
  Object.defineProperty(event, "source", { value: source });
  window.dispatchEvent(event);
}

describe("the approval hint's slow line", () => {
  it("shows the help line at 15 s when no OpenKey window has loaded", async () => {
    const more = show();
    await vi.advanceTimersByTimeAsync(APPROVAL_SLOW_AFTER_MS);
    expect(more.hidden).toBe(false);
    expect(more.textContent).toBe(APPROVAL_SLOW_COPY);
  });

  it("does not show the help line after 20 s while the OpenKey window is up", async () => {
    const more = show();
    postReady(openKeyFrame());
    await vi.advanceTimersByTimeAsync(20_000);
    expect(more.hidden).toBe(true);
    expect(more.textContent).toBe("");
  });

  it("removes the help line when the OpenKey window loads after it appeared", async () => {
    const more = show();
    await vi.advanceTimersByTimeAsync(APPROVAL_SLOW_AFTER_MS);
    expect(more.textContent).toBe(APPROVAL_SLOW_COPY);
    postReady(openKeyFrame());
    expect(more.hidden).toBe(true);
    expect(more.textContent).toBe("");
  });

  it("keeps showing the help line for a top-level popup, whose parent is itself (the popup fallback)", async () => {
    const more = show();
    postReady(popupWindow());
    await vi.advanceTimersByTimeAsync(APPROVAL_SLOW_AFTER_MS);
    expect(more.textContent).toBe(APPROVAL_SLOW_COPY);
  });

  it("keeps showing the help line for a ready from another origin", async () => {
    const more = show();
    postReady(openKeyFrame(), "https://elsewhere.example");
    await vi.advanceTimersByTimeAsync(APPROVAL_SLOW_AFTER_MS);
    expect(more.textContent).toBe(APPROVAL_SLOW_COPY);
  });

  it("does not take an origin that only starts with the OpenKey origin", async () => {
    const more = show();
    postReady(openKeyFrame(), `${OPENKEY_ORIGIN}.evil.example`);
    await vi.advanceTimersByTimeAsync(APPROVAL_SLOW_AFTER_MS);
    expect(more.textContent).toBe(APPROVAL_SLOW_COPY);
  });

  it("leaves the timeout line alone at 60 s", async () => {
    const more = show();
    postReady(openKeyFrame());
    await vi.advanceTimersByTimeAsync(60_000);
    expect(more.hidden).toBe(false);
    expect(more.textContent).toBe(TIMEOUT_COPY);
  });
});
