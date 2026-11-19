// Clicking and counting OpenKey approvals in the sender sign-in smoke (TC-2310). The in-page
// functions are self-contained (Puppeteer serializes them into the frame) and take the document or
// element, so they can be unit tested.
import { APPROVE_NAME, ELEVATED_ALLOW_NAME, scrub } from "./smoke-redact.mjs";

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

/**
 * OpenKey's extra warning for elevated permissions (TC-2927), which an Approve click opens in place
 * of the review: `{ shown: false }` when it isn't showing; otherwise its title, one card heading per
 * elevated permission (the heading's first span; the second is the "Sensitive" pill), and `allow`:
 * its last button when that is the enabled whole-request action named `allowName`, else null. A
 * request OpenKey can split ends in per-card choices and Continue instead; that is never clicked.
 */
export function elevatedScreen(allowName, doc = document) {
  const visible = (element) => element.getClientRects().length > 0;
  const label = (element) => (element.textContent ?? "").replace(/\s+/g, " ").trim();
  const screen = [...doc.querySelectorAll('[role=dialog][aria-labelledby="elevated-title"]')].filter(visible).at(-1);
  if (screen === undefined) return { shown: false };
  const title = screen.querySelector("#elevated-title");
  const last = [...screen.querySelectorAll("button")].filter(visible).at(-1);
  return {
    shown: true,
    title: title ? label(title) : "",
    cards: [...screen.querySelectorAll("[role=group] h2")].map((heading) => label(heading.querySelector("span") ?? heading)),
    allow: last !== undefined && !last.disabled && new RegExp(allowName).test(label(last)) ? last : null,
  };
}

/** Whether the last visible dialog's last button reads "Signing…" (OpenKey took the approval). */
export function signingShown(doc = document) {
  const visible = (element) => element.getClientRects().length > 0;
  const dialog = [...doc.querySelectorAll("[role=dialog]")].filter(visible).at(-1);
  const button = dialog ? [...dialog.querySelectorAll("button")].filter(visible).at(-1) : undefined;
  return (button?.textContent ?? "").replace(/\s+/g, " ").trim() === "Signing…";
}

/**
 * Why the smoke must not click "Allow and approve" on the warning `shown` (`{ title, cards, whole }`),
 * or null. `expected` is what the step's own request makes OpenKey show: `{ site, cards, required }`;
 * every shown card must be in `cards` and every card in `required` must be shown. Without
 * `expected` the step's request must not reach the warning at all.
 */
export function elevatedRefusal(shown, expected) {
  if (!expected) return "not expected at this step";
  if (shown.title !== `${expected.site} is asking for more access`) return `unexpected title: ${shown.title}`;
  const unexpected = shown.cards.filter((card) => !expected.cards.includes(card));
  if (unexpected.length > 0) return `unexpected permission: ${unexpected.join("; ")}`;
  const missing = expected.required.filter((card) => !shown.cards.includes(card));
  if (missing.length > 0) return `missing permission: ${missing.join("; ")}`;
  if (!shown.whole) return "no Allow and approve (a request OpenKey can split)";
  return null;
}

const pause = (ms) => new Promise((done) => setTimeout(done, ms));

/** The elevated warning in frame `sign` with its facts read out, or null when it isn't showing. The caller disposes `screen`. */
async function readElevated(sign) {
  const screen = await sign.evaluateHandle(elevatedScreen, ELEVATED_ALLOW_NAME.source).catch(() => null);
  if (screen === null) return null;
  const facts = await screen.evaluate((found) => ({ shown: found.shown, title: found.title, cards: found.cards, whole: Boolean(found.allow) })).catch(() => null);
  if (facts?.shown) return { ...facts, screen };
  await screen.dispose();
  return null;
}

/**
 * The warning is showing in `sign`: records it in `report.elevatedScreens` (step, title, card
 * headings, whether its "Allow and approve" was taken) and clicks "Allow and approve" only when
 * `elevatedRefusal` finds nothing; a refusal goes to `report.elevatedRefused`, nothing is clicked.
 * Taken, as for Approve, once the review closes, a sign call starts after the click, or the review's
 * Approve (which OpenKey presses itself after the warning) reads "Signing…"; otherwise a drop.
 */
async function allowElevated({ sign, during, report, closed, signedSince, at, stage, takenMs, elevated }, shown) {
  try {
    const entry = { during, stage: stage(), atMs: at(), title: scrub(shown.title).slice(0, 80), cards: shown.cards.map((card) => scrub(card).slice(0, 80)), wholeRequest: shown.whole, allowed: false };
    report.elevatedScreens ??= [];
    if (report.elevatedScreens.length < 10) report.elevatedScreens.push(entry);
    const refused = elevatedRefusal(shown, elevated);
    if (refused !== null) {
      entry.refused = scrub(refused).slice(0, 200);
      report.elevatedRefused ??= { during, stage: entry.stage, reason: entry.refused };
      return false;
    }
    const button = (await shown.screen.getProperty("allow")).asElement();
    if (!button) return false;
    const clickedAt = at();
    // DOM .click() is untrusted; OpenKey refuses it inside an iframe.
    await button.click();
    const taken = async () => closed() || signedSince(clickedAt) || await sign.evaluate(signingShown).catch(() => false);
    const deadline = Date.now() + takenMs;
    while (Date.now() < deadline) {
      if (await taken()) { entry.allowed = true; return true; }
      await pause(50);
    }
    if (await taken()) { entry.allowed = true; return true; }
    report.approveClicksNotTaken = (report.approveClicksNotTaken ?? 0) + 1;
    (report.approveClicksDropped ??= []).push({ during, stage: stage(), atMs: clickedAt, screen: "elevated" });
    return false;
  } finally {
    await shown.screen.dispose();
  }
}

/**
 * Clicks OpenKey's Approve in frame `sign` with real browser input and resolves whether the review
 * took the click within `takenMs`: the review closed or detached (`closed()`), a completed OpenKey
 * sign call started after the click (`signedSince(atMs)`), or the clicked button reads "Signing…".
 * A button that is only disabled is not taken yet; if it re-enables without any of those, or time
 * runs out, the click is a drop: reported in `report` (`approveClicksNotTaken`, one
 * `approveClicksDropped` entry: `during`, stage, timing, whether it was disabled without signing,
 * whether the button moved and what the click point hit) and the caller clicks again. A rejected
 * label goes to `approveLabelsRejected`. `at()` is the run clock; `stage()` the stage.
 *
 * When the click opens OpenKey's extra warning (TC-2927), or the warning is already showing, the
 * result is that of its "Allow and approve" instead (`allowElevated`), clicked only when the warning
 * shows what `elevated` expects for this step; Approve plus the warning count as one approval.
 */
export async function clickApprove({ sign, during, report, closed, signedSince = () => false, at, stage, reviewSeenAt, takenMs = 5_000, elevated = null }) {
  const context = { sign, during, report, closed, signedSince, at, stage, takenMs, elevated };
  const open = await readElevated(sign);
  if (open !== null) return allowElevated(context, open);
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
      const opened = await readElevated(sign);
      if (opened !== null) return allowElevated(context, opened);
      const state = await button.evaluate(clickState).catch(() => null);
      // Known limit: a reworded signing label plus a sign call slower than takenMs reads as a drop;
      // the retry finds no enabled Approve, so nothing is clicked twice, and the signature check holds.
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

const SIGN_ORIGIN = /^https:\/\/(api\.)?openkey\.so$/;
const SIGN_PATH = /^\/api\/(keys\/[^/]+\/sign|delegate\/authorize-sign)$/;

/** A completed OpenKey sign call in the smoke's trail (`/api/keys/<id>/sign` or `/api/delegate/authorize-sign`, 2xx). */
export const isSignature = (entry) => SIGN_ORIGIN.test(entry.origin ?? "") && entry.method === "POST"
  && SIGN_PATH.test(entry.path ?? "") && entry.status >= 200 && entry.status < 300;

/** OpenKey signature calls in `requests` (the smoke's trail) that started in `stage`. */
export const signaturesIn = (requests, stage) => requests.filter((entry) => entry.stage === stage && isSignature(entry)).length;

/**
 * For a smoke without a request trail: records each OpenKey sign call `page` makes into `calls`
 * (shared across pages), with the step it STARTED in (`step()`) and its start time (`at()`). A call
 * that completes 2xx is pushed to `calls.signed`; calls still open are in `calls.open`. Requests of
 * the page's frames, cross-origin ones included, arrive on the page. Watching a page twice is a no-op.
 */
const watched = new WeakSet();
export function watchSignatures(page, { calls, step, at }) {
  calls.signed ??= [];
  calls.open ??= new Map();
  if (watched.has(page)) return calls;
  watched.add(page);
  page.on("request", (request) => {
    let url;
    try { url = new URL(request.url()); } catch { return; }
    if (request.method() === "POST" && SIGN_ORIGIN.test(url.origin) && SIGN_PATH.test(url.pathname)) calls.open.set(request, { step: step(), atMs: at() });
  });
  const settle = (request, status) => {
    const call = calls.open.get(request);
    if (call === undefined) return;
    calls.open.delete(request);
    if (status >= 200 && status < 300) calls.signed.push(call);
  };
  page.on("requestfinished", (request) => settle(request, request.response()?.status() ?? 0));
  page.on("requestfailed", (request) => settle(request, 0));
  return calls;
}
/** Completed sign calls in `calls` for one step. */
export const signaturesFor = (calls, step) => (calls.signed ?? []).filter((call) => call.step === step).length;
/** Whether a sign call that started at or after `fromMs` has completed. */
export const signedSince = (calls, fromMs) => (calls.signed ?? []).some((call) => call.atMs >= fromMs);

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
