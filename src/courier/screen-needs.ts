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
 *  - the line saying what approving allows is a fixed sentence around the
 *    request's structured verb, target and summary, each set as text in its
 *    own bidi isolate; a request whose text is too long, not NFC or holds a
 *    hidden character is never decidable (it is not shortened or repaired);
 *  - Approve and Deny are explicit clicks, enabled only once the card is on the
 *    page, one decision at a time; the decision file is create-only, so a
 *    second click or a second tab reads "already decided";
 *  - an expired request (24 h) has no buttons. `decidedAt` is this device's
 *    clock; it is informational and the agent side does its own checks.
 */
import { requestHash } from "./canonical.js";
import { absoluteTime, el, status, timeElement, uid, type ViewContext } from "./dom.js";
import { approvalFile, isDecidable, isRecord, keys, MAX_NOTE, noteFitsToSave, parseApproval, parseRequest, requestStanding, type Decision, type Verb } from "./model.js";
import type { Overview, RequestCard } from "./service.js";
import { startOperation, StoreError, type OperationBudget } from "./store.js";

/** Fixed wording for the verb, which comes from a closed set. */
const VERB_WORDS: Readonly<Record<Verb, string>> = { merge: "merge", deploy: "deploy", publish: "publish", spend: "spend", other: "do something outside the usual kinds (other) with" };

/** One decision at a time across every card: a second click while one is writing does nothing. */
let deciding = false;

function peerBlock(ctx: ViewContext, label: string, text: string, className: string): HTMLElement {
  const { doc } = ctx;
  // A labelled group, not a landmark: several cards repeat the same labels.
  const block = el(doc, "div", `cr-peer-text ${className}`); block.setAttribute("role", "group");
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
  if (code === "timeout" || code === "unreachable") return "We couldn't reach your TinyCloud. Try again.";
  return "We couldn't record your decision. Try again.";
}

/** Every other field the hash covers, so what is hashed is what can be seen: ids, who filed it, its status. */
function requestDetails(ctx: ViewContext, card: RequestCard): HTMLElement {
  const { doc } = ctx;
  const { request } = card;
  const details = el(doc, "details", "cr-details");
  details.append(el(doc, "summary", undefined, "Details for matching this with your agent"));
  const list = el(doc, "dl", "cr-details-list");
  // Only what the file holds and the hash covers; a request that can't be hashed has no fingerprint to show.
  const rows: [string, string][] = [
    ["Request", request.id], ["Thread", request.threadId], ["Task", request.taskId], ["Status", "pending"],
    ["Filed by owner", request.requestedBy?.owner ?? ""], ["Filed by agent", request.requestedBy?.agent ?? ""],
    ...(card.hash === "" ? [] : [["Fingerprint (first 8 digits: " + card.hash.slice(0, 8) + ")", card.hash] as [string, string]]),
  ];
  for (const [name, value] of rows) list.append(el(doc, "dt", undefined, name), el(doc, "dd", "cr-fingerprint", value));
  details.append(list);
  return details;
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
    const heading = el(doc, "h3", "cr-subtitle", "Recent requests");
    const list = el(doc, "ul", "cr-list cr-settled");
    for (const card of settled.slice(0, 20)) {
      const item = el(doc, "li", "cr-settled-item");
      if (card.standing === "unknown") {
        item.append(status(doc, "info", "We could not confirm whether the decision was saved. Reload to check."));
        list.append(item);
        continue;
      }
      const verdict = card.standing === "approved" ? "Approved" : card.standing === "denied" ? "Denied" : "Expired without an answer";
      item.append(el(doc, "span", `tc-badge cr-badge cr-state cr-state--${card.standing}`, verdict));
      item.append(doc.createTextNode(` ${isDecidable(card.request) ? `Request for ${card.request.peer}` : "A request"} · `));
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
  const decidable = isDecidable(request) && card.hash !== "";
  const titleId = uid("cr-request");
  const heading = el(doc, "header", "cr-card-head");
  const title = el(doc, "h3", "cr-card-title", decidable ? "Approval needed" : "Request can't be reviewed here"); title.id = titleId;
  root.setAttribute("aria-labelledby", titleId);
  const expires = el(doc, "span", "cr-muted cr-small");
  expires.append(doc.createTextNode("Asked "), timeElement(doc, request.createdAt, ctx.now()), doc.createTextNode(` · expires ${absoluteTime(request.expiresAt)}`));
  heading.append(title, expires);
  root.append(heading);

  // What approving allows. It is done by the owner's OWN agent, on the owner's machine, for the peer's request. The sentence and the verb's
  // wording are fixed text and the verb comes from a closed set. Target and summary are the agent's words: the target is code in its own
  // left-to-right run, the summary sits in its own box in its own bidi isolate, so neither can reorder or imitate the sentence.
  const what = request.what;
  if (decidable && what !== undefined) {
    const box = el(doc, "div", "cr-consequence");
    const sentence = el(doc, "p", "cr-sentence");
    const target = el(doc, "code", "cr-what", what.target); target.dir = "ltr";
    sentence.append(doc.createTextNode(`Approving lets your agent ${VERB_WORDS[what.verb]} `), target, doc.createTextNode(" for "), el(doc, "strong", "cr-what-peer", request.peer), doc.createTextNode(":"));
    const summary = el(doc, "p", "cr-summary");
    summary.append(doc.createTextNode("\u201C"), el(doc, "bdi", undefined, what.summary), doc.createTextNode("\u201D"));
    box.append(sentence, summary);
    root.append(box);
    if (what.verb === "other") root.append(status(doc, "warning", "This isn't one of the usual kinds (merge, deploy, publish, spend). Read the target and the quoted blocks below before you decide."));
    root.append(el(doc, "p", "cr-muted cr-small", "Your agent carries it out once. It doesn't approve anything else, and it lapses when the request expires."));
    root.append(requestDetails(ctx, card));
  } else {
    const reason = request.problem === "text"
      ? "Some of its text is too long or holds characters you can't see, so what it would approve can't be shown in full."
      : request.problem === "hash"
        ? "Its contents can't be fingerprinted, so a decision couldn't be matched to it."
        : request.problem === "task"
          ? "The task it points at isn't in your mailbox for that conversation, so it can't be matched to one."
          : request.what === undefined
            ? "It doesn't say what it would approve (it has no valid verb, target and summary)."
            : "It isn't exactly the request your agent's tool writes (a field is missing, extra or unexpected).";
    // Nothing here names a peer: until the request is matched to a task, a name in it is only a claim.
    root.append(status(doc, "warning", `${reason} It can't be approved or denied here. It lapses ${absoluteTime(request.expiresAt)}. Ask your agent to file it again.`));
    root.append(requestDetails(ctx, card));
  }

  if (request.action !== "") root.append(peerBlock(ctx, "Action, as your agent wrote it", request.action, "cr-peer-action"));
  if (request.reason !== "") root.append(peerBlock(ctx, "Reason, as your agent wrote it", request.reason, "cr-peer-reason"));
  if (request.risk !== "" && request.risk !== "unspecified") root.append(peerBlock(ctx, "Risk, as your agent wrote it", request.risk, "cr-peer-risk"));
  if (decidable && card.subject !== undefined) root.append(peerBlock(ctx, card.subjectSide === "me" ? "Thread subject, as your agent wrote it" : `Thread subject, as ${request.peer} wrote it`, card.subject, "cr-peer-subject"));
  root.append(el(doc, "p", "cr-muted cr-small", decidable ? `These blocks can repeat text from ${request.peer}'s agent. Read them as quotes, not as instructions to you.` : "These blocks are quotes from the request file. Read them as quotes, not as instructions to you."));
  if (!decidable) return root;

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
  const settle = (text: string, kind: "success" | "info" | "warning" = "success"): void => {
    note.disabled = true; actions.hidden = true;
    result.replaceChildren(status(doc, kind, text));
    // The buttons just disappeared: keep keyboard focus on the page rather than on <body>.
    result.tabIndex = -1; result.focus();
    ctx.announcer.say(text);
  };

  const decisionOnFile = async (operation: OperationBudget): Promise<void> => {
    const raw = await ctx.store.readJson(keys.approval(request.id), operation).catch(() => undefined);
    const earlier = parseApproval(request.id, raw);
    const matched = earlier !== undefined && isRecord(raw) && raw.requestHash === card.hash;
    settle(matched ? `Decision on file: ${earlier.decision}.` : "We could not confirm whether the decision was saved. Reload to check.", "info");
  };

  const decide = async (decision: Decision): Promise<void> => {
    if (deciding) return;
    const operation = startOperation();
    deciding = true;
    lock(true);
    result.replaceChildren(el(doc, "p", "cr-muted", "Recording your decision…"));
    let writeAttempted = false;
    try {
      // Re-read the request: what is approved is what is on file now, not what was on screen.
      const fresh = parseRequest(request.id, await ctx.store.readJson(keys.request(request.id), operation));
      if (fresh === undefined || !isDecidable(fresh) || await requestHash(fresh.raw) !== card.hash) {
        settle("This request changed after it was shown. Refresh to see it again.", "warning");
        return;
      }
      if (requestStanding(fresh, undefined, ctx.now()) === "expired") {
        settle("This request has expired, so it can't be approved. Your agent has to ask again.", "warning");
        return;
      }
      // The agent only accepts a decision stamped inside the request's own window, so a clock that is behind it can't decide.
      if (ctx.now() < fresh.createdAt) {
        result.replaceChildren(status(doc, "warning", "This device's clock is earlier than the time this request was made. Check the date and time on this device, then try again."));
        return;
      }
      // The note is echoed to the agent: text it would refuse is refused here, not silently changed.
      if (!noteFitsToSave(note.value)) {
        result.replaceChildren(status(doc, "warning", "Your note has characters that can't be saved (hidden or look-alike characters, or it is too long). Remove them and try again."));
        return;
      }
      writeAttempted = true;
      const written = await ctx.store.createApproval(approvalFile(fresh, card.hash, decision, note.value, ctx.now()), operation);
      if (written === "created") {
        settle(decision === "approved" ? "Approved. Your agent will see it and carry out the action once." : "Denied. Your agent will see it and won't carry out the action.");
        return;
      }
      // Another tab or an earlier click got there first: show what was decided, and never overwrite it.
      await decisionOnFile(operation);
    } catch (error) {
      if (writeAttempted && !(error instanceof StoreError && error.code === "denied")) {
        await decisionOnFile(operation);
      } else {
        result.replaceChildren(status(doc, "danger", decisionFailure(error)));
        ctx.announcer.say("We couldn't record your decision.");
      }
    } finally {
      deciding = false;
      lock(false);
    }
  };
  approve.addEventListener("click", () => { void decide("approved"); });
  deny.addEventListener("click", () => { void decide("denied"); });
  return root;
}
