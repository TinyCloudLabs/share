// In-page checks for counting OpenKey approvals in the sender sign-in smoke (TC-2310). Each function
// is self-contained (Puppeteer serializes it into the page), and takes the document or element so it
// can be unit tested with jsdom.

/**
 * Whether OpenKey took an Approve click: its Approve button is gone, disabled, or reads "Signing…".
 * A button still named Approve (or Approve exact bytes) and enabled means the click did not register.
 */
export function approvalTaken(doc = document) {
  const button = [...doc.querySelectorAll("button")].find((candidate) => /^(Approve( exact bytes)?|Signing…)$/.test((candidate.textContent ?? "").trim()));
  return button === undefined || button.disabled || (button.textContent ?? "").trim() === "Signing…";
}

/**
 * What a click at the centre of `element` would hit inside its own document: whether that is the
 * element (or inside it), and the hit element's tag and classes. No text is read.
 */
export function clickPointHit(element) {
  const rect = element.getBoundingClientRect();
  const hit = element.ownerDocument.elementFromPoint(rect.x + rect.width / 2, rect.y + rect.height / 2);
  return {
    onButton: hit !== null && (hit === element || element.contains(hit)),
    tag: hit?.tagName?.toLowerCase() ?? null,
    classes: typeof hit?.className === "string" ? hit.className.slice(0, 80) : null,
  };
}

/** How far a box moved (px, the larger of x and y), or null if either box is missing. */
export function boxMoved(before, after) {
  if (!before || !after) return null;
  return Math.round(Math.max(Math.abs(after.x - before.x), Math.abs(after.y - before.y), Math.abs(after.height - before.height)));
}
