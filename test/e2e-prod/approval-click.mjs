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

/** Whether the clicked Approve took the click: it left the page, went disabled, or reads "Signing…". */
export function clickTaken(element) {
  return !element.isConnected || element.disabled || (element.textContent ?? "").trim() === "Signing…";
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
 * took the click (the frame closed or detached, or the clicked button left, went disabled or reads
 * "Signing…", within `takenMs`). A click that wasn't taken is reported in `report`
 * (`approveClicksNotTaken`, one `approveClicksDropped` entry: `during`, stage, timing, whether the
 * button moved and what the click point hit); a rejected label goes to `approveLabelsRejected`.
 * `closed()` says whether the review frame is gone; `at()` is the run clock; `stage()` the stage.
 */
export async function clickApprove({ sign, during, report, closed, at, stage, reviewSeenAt, takenMs = 5_000 }) {
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
    while (Date.now() < deadline) {
      if (closed() || await button.evaluate(clickTaken).catch(() => closed())) return true;
      await pause(100);
    }
    await pause(150);
    const boxAfter = await button.boundingBox().catch(() => null);
    report.approveClicksNotTaken = (report.approveClicksNotTaken ?? 0) + 1;
    (report.approveClicksDropped ??= []).push({
      during, stage: stage(), atMs: clickedAt,
      msSinceReview: reviewSeenAt === undefined ? null : clickedAt - reviewSeenAt,
      buttonMovedPx: boxMoved(boxBefore, boxAfter),
      clickPointOnButton: hit?.onButton ?? null, clickPointTag: hit?.tag ?? null, clickPointClasses: hit?.classes ?? null,
    });
    return false;
  } finally {
    await picked.dispose();
  }
}

/** OpenKey signature calls (a completed sign) in `requests` (the smoke's trail) that started in `stage`. */
export const signaturesIn = (requests, stage) => requests.filter((entry) => entry.stage === stage
  && /^https:\/\/(api\.)?openkey\.so$/.test(entry.origin ?? "") && entry.method === "POST"
  && /^\/api\/(keys\/[^/]+\/sign|delegate\/authorize-sign)$/.test(entry.path ?? "")
  && entry.status >= 200 && entry.status < 300).length;

/**
 * Why a step's counted approvals and OpenKey's signatures disagree, or null: more signatures than
 * approvals (a review hidden behind a click reported as dropped), or approvals with no signature at
 * all (a click wrongly counted as taken, or a sign call the trail no longer recognises).
 */
export function signatureMismatch(prompts, signatures) {
  if (signatures > prompts) return `${signatures} OpenKey signatures for ${prompts} counted approvals`;
  if (prompts > 0 && signatures === 0) return `${prompts} counted approvals but no OpenKey signature`;
  return null;
}
