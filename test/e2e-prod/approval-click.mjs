// Clicking and counting OpenKey approvals in the sender sign-in smoke (TC-2310). The in-page
// functions are self-contained (Puppeteer serializes them into the frame) and take the document or
// element, so they can be unit tested.
import { APPROVE_NAME, scrub } from "./smoke-redact.mjs";

/**
 * OpenKey's primary action: the last visible button of the last visible approval dialog (Cancel
 * comes first), and only if its name is one of the approval's labels (`approveName`, the source of
 * APPROVE_NAME); without a dialog, the button named Approve or Approve exact bytes. Anything else is
 * not clicked: `{ button: null, rejected: <its label> }`. A disabled match is `{ button: null }`.
 */
export function approvePick(approveName, doc = document) {
  const named = new RegExp(approveName);
  const visible = (element) => element.getClientRects().length > 0;
  const label = (element) => (element.textContent ?? "").replace(/\s+/g, " ").trim();
  const dialog = [...doc.querySelectorAll("[role=dialog]")].filter(visible).at(-1);
  const button = dialog
    ? [...dialog.querySelectorAll("button")].filter(visible).at(-1)
    : [...doc.querySelectorAll("button")].filter(visible).find((candidate) => /^Approve( exact bytes)?$/.test(label(candidate)));
  if (button === undefined) return { button: null, rejected: "" };
  if (!named.test(label(button))) return { button: null, rejected: label(button) };
  return { button: button.disabled ? null : button, rejected: "" };
}

/**
 * The clicked Approve's state. "Signing…" means OpenKey took the click. Disabled alone does NOT:
 * OpenKey also disables Approve for a moment after every resize of the review (TC-2320), so a missed
 * click can be followed by a disabled button that re-enables.
 */
export function clickState(element) {
  const label = (element.textContent ?? "").trim();
  return { connected: element.isConnected, disabled: element.disabled, signing: label === "Signing…" };
}

/** What a click at the centre of `element` would hit in its own document (no text is read). */
export function clickPointHit(element) {
  const rect = element.getBoundingClientRect();
  const hit = element.ownerDocument.elementFromPoint(rect.x + rect.width / 2, rect.y + rect.height / 2);
  return {
    onButton: hit !== null && (hit === element || element.contains(hit)),
    tag: hit?.tagName?.toLowerCase() ?? null,
    classes: typeof hit?.className === "string" ? hit.className.slice(0, 80) : null,
  };
}

/** How far a box moved (px, the largest of the x, y and height changes), or null if either is missing. */
export function boxMoved(before, after) {
  if (!before || !after) return null;
  return Math.round(Math.max(Math.abs(after.x - before.x), Math.abs(after.y - before.y), Math.abs(after.height - before.height)));
}

const pause = (ms) => new Promise((done) => setTimeout(done, ms));

/**
 * Clicks OpenKey's Approve in frame `sign` with real browser input and resolves whether the review
 * took the click within `takenMs`: the review closed or detached (`closed()`), a completed OpenKey
 * sign call started after the click (`signedSince(atMs)`), or the clicked button reads "Signing…".
 * A button that is only disabled is not taken yet; if it re-enables without any of those, or time
 * runs out, the click is a drop: reported in `report` (`approveClicksNotTaken`, one
 * `approveClicksDropped` entry: `during`, stage, timing, whether it was disabled without signing,
 * whether the button moved and what the click point hit) and the caller clicks again. A rejected
 * label goes to `approveLabelsRejected`. `at()` is the run clock; `stage()` the stage.
 */
export async function clickApprove({ sign, during, report, closed, signedSince = () => false, at, stage, reviewSeenAt, takenMs = 5_000 }) {
  const picked = await sign.evaluateHandle(approvePick, APPROVE_NAME.source);
  try {
    const rejected = await (await picked.getProperty("rejected")).jsonValue();
    if (rejected) {
      const labels = new Set(report.approveLabelsRejected ?? []);
      if (labels.size < 5) report.approveLabelsRejected = [...labels.add(scrub(rejected).slice(0, 40))];
    }
    const button = (await picked.getProperty("button")).asElement();
    if (!button) return false;
    const boxBefore = await button.boundingBox().catch(() => null);
    const hit = await button.evaluate(clickPointHit).catch(() => null);
    const clickedAt = at();
    // DOM .click() is untrusted; OpenKey refuses it inside an iframe.
    await button.click();
    const deadline = Date.now() + takenMs;
    let disabledWithoutSigning = false;
    while (Date.now() < deadline) {
      if (closed() || signedSince(clickedAt)) return true;
      const state = await button.evaluate(clickState).catch(() => null);
      if (state?.signing) return true;
      if (state?.connected && state.disabled) disabledWithoutSigning = true;
      // Re-enabled with no sign call and no "Signing…": the click missed (the disable was a layout block).
      else if (state?.connected && disabledWithoutSigning) break;
      await pause(50);
    }
    if (closed() || signedSince(clickedAt)) return true;
    await pause(150);
    const boxAfter = await button.boundingBox().catch(() => null);
    report.approveClicksNotTaken = (report.approveClicksNotTaken ?? 0) + 1;
    (report.approveClicksDropped ??= []).push({
      during, stage: stage(), atMs: clickedAt,
      msSinceReview: reviewSeenAt === undefined ? null : clickedAt - reviewSeenAt,
      disabledWithoutSigning,
      buttonMovedPx: boxMoved(boxBefore, boxAfter),
      clickPointOnButton: hit?.onButton ?? null, clickPointTag: hit?.tag ?? null, clickPointClasses: hit?.classes ?? null,
    });
    return false;
  } finally {
    await picked.dispose();
  }
}

/** A completed OpenKey sign call in the smoke's trail (`/api/keys/<id>/sign` or `/api/delegate/authorize-sign`, 2xx). */
export const isSignature = (entry) => /^https:\/\/(api\.)?openkey\.so$/.test(entry.origin ?? "") && entry.method === "POST"
  && /^\/api\/(keys\/[^/]+\/sign|delegate\/authorize-sign)$/.test(entry.path ?? "")
  && entry.status >= 200 && entry.status < 300;

/** OpenKey signature calls in `requests` (the smoke's trail) that started in `stage`. */
export const signaturesIn = (requests, stage) => requests.filter((entry) => entry.stage === stage && isSignature(entry)).length;

/**
 * Why a step's counted approvals and OpenKey's signatures differ, or null. They must be equal: more
 * signatures means a review hid behind a click reported as dropped; fewer means a click was counted
 * that OpenKey never signed for (a missed click that looked taken). Holds for the exact-bytes
 * approval Share uses today: one Approve, one signature. (A preview flow, a preview click and then
 * "Approve exact bytes", would count two approvals for one signature and fail here.)
 */
export function signatureMismatch(prompts, signatures) {
  return signatures === prompts ? null : `${signatures} OpenKey signatures for ${prompts} counted approvals`;
}
