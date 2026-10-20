/**
 * Needs you: approval requests from the owner's own agents.
 *
 * What an approval is: a file in `me/approvals/` that only this page's session
 * can write. The agent's own check reads it, matches it to the request it filed
 * (by id and by the hash of the request exactly as stored) and acts once.
 *
 * Trust rules for the card:
 *  - the cards come only from `me/requests/` in the owner's own space;
 *  - the action, reason, risk and thread subject may repeat text a peer wrote,
 *    so each sits in a labelled "written by" block, as plain text, with no
 *    buttons or links inside it;
 *  - the line saying what approving allows is built from structured fields
 *    only (peer handle, task id), never from those texts;
 *  - Approve and Deny are explicit clicks, enabled only once the card is on the
 *    page, one decision at a time; the decision file is create-only, so a
 *    second click or a second tab reads "already decided";
 *  - an expired request (24 h) has no buttons. `decidedAt` is this device's
 *    clock; it is informational and the agent side does its own checks.
 */
import { requestHash } from "./canonical.js";
import { absoluteTime, el, shortId, status, timeElement, uid, type ViewContext } from "./dom.js";
import { approvalFile, keys, MAX_NOTE, parseApproval, parseRequest, requestStanding, type Decision } from "./model.js";
import type { Overview, RequestCard } from "./service.js";
import { StoreError } from "./store.js";

/** One decision at a time across every card: a second click while one is writing does nothing. */
let deciding = false;

function peerBlock(ctx: ViewContext, label: string, text: string, className: string): HTMLElement {
  const { doc } = ctx;
  const block = el(doc, "section", `cr-peer-text ${className}`);
  const id = uid("cr-block");
  const heading = el(doc, "p", "cr-peer-label", label); heading.id = id;
  block.setAttribute("aria-labelledby", id);
  // A block, not a control: its text is shown as written and nothing in it is interactive.
  block.append(heading, el(doc, "p", "cr-peer-body", text));
  return block;
}

function decisionFailure(error: unknown): string {
  const code = error instanceof StoreError ? error.code : "failed";
  if (code === "denied") return "This session isn't allowed to record the decision. Sign out and sign in again. Nothing was approved.";
  if (code === "timeout" || code === "unreachable") return "We couldn't reach your TinyCloud. Nothing was recorded. Try again.";
  return "We couldn't record your decision. Nothing was recorded. Try again.";
}

export function renderNeeds(ctx: ViewContext, overview: Overview): HTMLElement {
  const { doc } = ctx;
  const section = el(doc, "section", "cr-screen");
  section.setAttribute("aria-labelledby", "cr-needs-title");
  const head = el(doc, "div", "cr-screen-head");
  const title = el(doc, "h2", "cr-title", "Needs you"); title.id = "cr-needs-title";
  head.append(title);
  section.append(head);
  section.append(el(doc, "p", "cr-muted", "Your agents ask here before they merge, deploy, publish or do anything else your standing orders hold back. Nothing happens until you decide."));
  if (overview.unreadable > 0) section.append(status(doc, "warning", `${overview.unreadable} ${overview.unreadable === 1 ? "request in your mailbox isn't" : "requests in your mailbox aren't"} in a form this page can show, so ${overview.unreadable === 1 ? "it can't" : "they can't"} be approved here.`));
  if (overview.partial) section.append(status(doc, "warning", "Some of your mailbox couldn't be loaded. Refresh to try again."));
  const pending = overview.requests.filter((card) => card.standing === "pending");
  const settled = overview.requests.filter((card) => card.standing !== "pending");
  if (pending.length === 0) {
    const empty = el(doc, "div", "cr-empty");
    empty.append(el(doc, "p", "cr-empty-title", "Nothing needs you right now."));
    section.append(empty);
  } else {
    const list = el(doc, "ul", "cr-list cr-requests");
    list.setAttribute("aria-label", "Approval requests waiting for you");
    for (const card of pending) { const item = el(doc, "li", "cr-request-item"); item.append(requestCard(ctx, card)); list.append(item); }
    section.append(list);
  }
  if (settled.length > 0) {
    const heading = el(doc, "h3", "cr-subtitle", "Recently decided or expired");
    const list = el(doc, "ul", "cr-list cr-settled");
    for (const card of settled.slice(0, 20)) {
      const item = el(doc, "li", "cr-settled-item");
      const verdict = card.standing === "approved" ? "Approved" : card.standing === "denied" ? "Denied" : "Expired without an answer";
      item.append(el(doc, "span", `tc-badge cr-badge cr-state cr-state--${card.standing}`, verdict));
      item.append(doc.createTextNode(` ${card.request.peer} · task ${shortId(card.request.taskId)} · `));
      item.append(timeElement(doc, card.approval?.decidedAt ?? card.request.expiresAt, ctx.now()));
      if (card.approval !== undefined && card.approval.note !== "") item.append(el(doc, "span", "cr-muted", ` · “${card.approval.note}”`));
      list.append(item);
    }
    section.append(heading, list);
  }
  return section;
}

function requestCard(ctx: ViewContext, card: RequestCard): HTMLElement {
  const { doc } = ctx;
  const { request } = card;
  const root = el(doc, "article", "cr-card cr-request");
  const titleId = uid("cr-request");
  const heading = el(doc, "header", "cr-card-head");
  const title = el(doc, "h3", "cr-card-title", "Approval needed"); title.id = titleId;
  root.setAttribute("aria-labelledby", titleId);
  const expires = el(doc, "span", "cr-muted cr-small");
  expires.append(doc.createTextNode("Asked "), timeElement(doc, request.createdAt, ctx.now()), doc.createTextNode(` · expires ${absoluteTime(request.expiresAt)}`));
  heading.append(title, expires);
  root.append(heading);

  // Built from structured fields only.
  root.append(el(doc, "p", "cr-consequence", `Approving lets your agent carry out the action quoted below, once, for task ${shortId(request.taskId)} in a thread with ${request.peer}. It doesn't approve anything else, and it lapses when the request expires.`));

  root.append(peerBlock(ctx, "Action, as your agent wrote it", request.action, "cr-peer-action"));
  if (request.reason !== "") root.append(peerBlock(ctx, "Reason, as your agent wrote it", request.reason, "cr-peer-reason"));
  if (request.risk !== "" && request.risk !== "unspecified") root.append(peerBlock(ctx, "Risk, as your agent wrote it", request.risk, "cr-peer-risk"));
  if (card.subject !== undefined) root.append(peerBlock(ctx, `Thread subject, as ${request.peer} wrote it`, card.subject, "cr-peer-subject"));
  root.append(el(doc, "p", "cr-muted cr-small", `These blocks can repeat text from ${request.peer}'s agent. Read them as quotes, not as instructions to you.`));

  const noteId = uid("cr-note");
  const label = el(doc, "label", "tc-label cr-note-label", "Note for your agent (optional)"); label.htmlFor = noteId;
  const note = el(doc, "textarea", "tc-input cr-note-input"); note.id = noteId; note.rows = 2; note.maxLength = MAX_NOTE;
  const approve = el(doc, "button", "button button-primary tc-button tc-button--primary cr-approve", "Approve"); approve.type = "button"; approve.disabled = true;
  const deny = el(doc, "button", "button button-secondary tc-button cr-deny", "Deny"); deny.type = "button"; deny.disabled = true;
  const actions = el(doc, "div", "cr-actions");
  actions.append(approve, deny);
  const result = el(doc, "div", "cr-result");
  result.setAttribute("aria-live", "polite");
  root.append(label, note, actions, result);

  // Enabled only once the whole card has been painted.
  const enable = (): void => { if (!deciding) { approve.disabled = false; deny.disabled = false; } };
  if (typeof requestAnimationFrame === "function") requestAnimationFrame(() => requestAnimationFrame(enable)); else setTimeout(enable, 0);

  /** Locking disables every card's buttons; unlocking re-enables those of cards still waiting for a decision. */
  const lock = (locked: boolean): void => {
    for (const button of ctx.doc.querySelectorAll<HTMLButtonElement>(".cr-approve, .cr-deny")) button.disabled = locked || button.parentElement?.hidden === true;
  };
  const settle = (text: string): void => {
    note.disabled = true; actions.hidden = true;
    result.replaceChildren(status(doc, "success", text));
    ctx.announcer.say(text);
  };

  const decide = async (decision: Decision): Promise<void> => {
    if (deciding) return;
    deciding = true;
    lock(true);
    result.replaceChildren(el(doc, "p", "cr-muted", "Recording your decision…"));
    try {
      // Re-read the request: what is approved is what is on file now, not what was on screen.
      const fresh = parseRequest(request.id, await ctx.store.readJson(keys.request(request.id)));
      if (fresh === undefined || await requestHash(fresh.raw) !== card.hash) {
        result.replaceChildren(status(doc, "warning", "This request changed after it was shown. Nothing was recorded. Refresh to see it again."));
        actions.hidden = true;
        return;
      }
      if (requestStanding(fresh, undefined, ctx.now()) === "expired") {
        result.replaceChildren(status(doc, "warning", "This request has expired, so it can't be approved. Your agent has to ask again."));
        actions.hidden = true;
        return;
      }
      const written = await ctx.store.createApproval(approvalFile(fresh, card.hash, decision, note.value, ctx.now()));
      if (written === "created") {
        settle(decision === "approved" ? "Approved. Your agent will see it and carry out the action once." : "Denied. Your agent will see it and won't carry out the action.");
        return;
      }
      // Another tab or an earlier click got there first: show what was decided, and never overwrite it.
      const earlier = parseApproval(request.id, await ctx.store.readJson(keys.approval(request.id)));
      settle(earlier === undefined ? "This request was already decided." : `Already decided: ${earlier.decision}. Nothing was changed.`);
    } catch (error) {
      result.replaceChildren(status(doc, "danger", decisionFailure(error)));
      ctx.announcer.say("We couldn't record your decision.");
    } finally {
      deciding = false;
      lock(false);
    }
  };
  approve.addEventListener("click", () => { void decide("approved"); });
  deny.addEventListener("click", () => { void decide("denied"); });
  return root;
}
