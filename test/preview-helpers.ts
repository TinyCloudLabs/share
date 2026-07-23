/**
 * Shared helpers for asserting on the SCRIPTLESS preview frame (spec §3.3,
 * src/viewer/preview-frame.ts). jsdom does not load srcdoc documents, so
 * the frame interior is inspected by parsing the srcdoc string with
 * DOMParser — which never executes scripts, mirroring the frame's own
 * sandbox="" guarantee.
 */
import { expect } from "vitest";

import { PREVIEW_FRAME_CLASS } from "../src/viewer/preview-frame.js";

/** The one preview iframe a rendered container must hold. */
export function previewFrameOf(container: HTMLElement): HTMLIFrameElement {
  const frame = container.querySelector<HTMLIFrameElement>(
    `iframe.${PREVIEW_FRAME_CLASS}`,
  );
  expect(frame, "preview frame missing from container").not.toBeNull();
  return frame as HTMLIFrameElement;
}

/**
 * Parse the frame's srcdoc document and return its <body>. Asserts the
 * structural isolation invariants every time the interior is inspected:
 * the sandbox attribute grants NOTHING (no allow-scripts, no
 * allow-same-origin — empty token list).
 */
export function previewBodyOf(container: HTMLElement): HTMLElement {
  const frame = previewFrameOf(container);
  expect(frame.getAttribute("sandbox"), "sandbox must grant nothing").toBe("");
  const doc = new DOMParser().parseFromString(frame.srcdoc, "text/html");
  return doc.body;
}

/**
 * The §3.3 containment invariant: the privileged document's content
 * container holds EXACTLY the preview iframe and nothing else — the
 * rendered document exists only as the frame's srcdoc payload. Returns the
 * parsed frame body for content assertions.
 */
export function assertContentIsolated(container: HTMLElement): HTMLElement {
  expect(container.children).toHaveLength(1);
  expect(container.firstElementChild?.tagName.toLowerCase()).toBe("iframe");
  return previewBodyOf(container);
}
