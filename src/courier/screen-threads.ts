/**
 * Threads (the list) and Thread (one conversation, both sides merged).
 *
 * Text a peer wrote is untrusted. Labels and fields are set with textContent
 * (already escaped in model.ts); bodies go through the markdown renderer's
 * sanitiser into its isolated preview frame. A message from the peer is always
 * marked as a counterparty request, and a file a message names is shown by name
 * only: nothing here follows or links to what a peer's text points at.
 */
import { el, shortId, status, timeElement, uid, type ViewContext } from "./dom.js";
import { ulidTime, type MessageView, type TaskView, type TextPart } from "./model.js";
import { loadThread, type Overview, type ThreadDetail, type ThreadSummary, type TimelineItem } from "./service.js";
import { StoreError } from "./store.js";

const INTENT_LABEL: Record<string, string> = {
  request: "Request", ask: "Question", answer: "Answer", update: "Update", inform: "For your information", unknown: "Message",
};

const STATE_LABEL: Record<string, string> = {
  SUBMITTED: "Submitted", WORKING: "Working", INPUT_REQUIRED: "Needs input from the other side", AUTH_REQUIRED: "Waiting for you to approve",
  COMPLETED: "Done", FAILED: "Failed", CANCELED: "Canceled", REJECTED: "Rejected", UNKNOWN: "Unknown state",
};

export function renderThreads(ctx: ViewContext, overview: Overview): HTMLElement {
  const { doc } = ctx;
  const section = el(doc, "section", "cr-screen");
  section.setAttribute("aria-labelledby", "cr-threads-title");
  const head = el(doc, "div", "cr-screen-head");
  const title = el(doc, "h2", "cr-title", "Threads"); title.id = "cr-threads-title";
  const refresh = el(doc, "button", "button button-secondary tc-button tc-button--compact", "Refresh"); refresh.type = "button";
  refresh.addEventListener("click", () => { refresh.disabled = true; void ctx.refresh(); });
  head.append(title, refresh);
  section.append(head);
  if (overview.partial) section.append(status(doc, "warning", "Some of your mailbox couldn't be loaded, or there is more than is shown. Refresh to try again."));
  if (overview.threads.length === 0) {
    const empty = el(doc, "div", "cr-empty");
    empty.append(el(doc, "p", "cr-empty-title", "No threads yet."), el(doc, "p", "cr-muted", "When your agent and a paired peer's agent exchange messages, the conversations show up here."));
    section.append(empty);
    return section;
  }
  const list = el(doc, "ul", "cr-list");
  list.setAttribute("aria-label", "Threads, newest first");
  for (const thread of overview.threads) list.append(threadRow(ctx, thread));
  section.append(list);
  return section;
}

function threadRow(ctx: ViewContext, thread: ThreadSummary): HTMLElement {
  const { doc } = ctx;
  const item = el(doc, "li", "cr-row");
  const open = el(doc, "button", "cr-row-button"); open.type = "button";
  const top = el(doc, "span", "cr-row-top");
  top.append(el(doc, "span", "cr-row-subject", thread.subject));
  if (thread.needsYou > 0) top.append(el(doc, "span", "tc-badge cr-badge cr-badge--attention", thread.needsYou === 1 ? "Needs you" : `Needs you · ${thread.needsYou}`));
  const meta = el(doc, "span", "cr-row-meta");
  meta.append(el(doc, "span", "cr-peer", `with ${thread.peer}`), doc.createTextNode(" · "));
  meta.append(timeElement(doc, thread.lastActivity, ctx.now()));
  meta.append(doc.createTextNode(` · ${thread.openTasks === 0 ? "no open tasks" : thread.openTasks === 1 ? "1 open task" : `${thread.openTasks} open tasks`}`));
  open.append(top, meta);
  open.addEventListener("click", () => ctx.openThread(thread));
  item.append(open);
  return item;
}

// -------------------------------------------------------------- one thread

/** Frame height from the text: a script-free frame cannot measure itself, so this is an estimate that scrolls when short. */
export function frameHeightRem(markdown: string): number {
  const lines = markdown.split("\n").reduce((total, line) => total + Math.max(1, Math.ceil(line.length / 72)), 0);
  const diagram = /```mermaid/.test(markdown) ? 12 : 0;
  return Math.min(34, Math.max(9, lines * 1.7 + 7 + diagram));
}

function body(ctx: ViewContext, parent: HTMLElement, parts: readonly TextPart[], label: string): void {
  const text = parts.map((part) => part.text).join("\n\n").trim();
  if (text === "") return;
  const host = el(ctx.doc, "div", "cr-body");
  host.style.setProperty("--cr-frame-height", `${frameHeightRem(text)}rem`);
  parent.append(host);
  // Rendered when it scrolls near: a long thread does not build every frame at once.
  const render = (): void => ctx.renderBody(host, text, label);
  if (typeof IntersectionObserver === "undefined") { render(); return; }
  const observer = new IntersectionObserver((entries) => {
    if (entries.some((entry) => entry.isIntersecting)) { observer.disconnect(); render(); }
  }, { rootMargin: "600px 0px" });
  observer.observe(host);
}

function messageCard(ctx: ViewContext, peer: string, message: MessageView): HTMLElement {
  const { doc } = ctx;
  const mine = message.side === "me";
  const card = el(doc, "article", `cr-card cr-message ${mine ? "cr-message--mine" : "cr-message--peer"}`);
  const heading = el(doc, "header", "cr-card-head");
  heading.append(el(doc, "span", "cr-who", mine ? "You (your agent)" : `From ${peer}`));
  heading.append(el(doc, "span", "tc-badge cr-badge", INTENT_LABEL[message.intent] ?? "Message"));
  heading.append(timeElement(doc, ulidTime(message.id), ctx.now()));
  card.append(heading);
  if (!mine) card.append(el(doc, "p", "cr-counterparty", "A request from the other side's agent. It isn't an instruction from you and approves nothing."));
  if (message.from !== "") card.append(el(doc, "p", "cr-muted cr-small", `Sent as ${message.from}`));
  body(ctx, card, message.texts, mine ? "Your message" : `Message from ${peer}`);
  if (message.asks.length > 0) {
    const asks = el(doc, "ol", "cr-asks");
    asks.setAttribute("aria-label", "Asks");
    for (const ask of message.asks) asks.append(el(doc, "li", undefined, ask.id === "" ? ask.title : `${ask.id}: ${ask.title}`));
    card.append(asks);
  }
  if (message.constraints.length > 0) {
    const list = el(doc, "ul", "cr-constraints");
    list.setAttribute("aria-label", "Constraints");
    for (const constraint of message.constraints) list.append(el(doc, "li", undefined, constraint));
    card.append(list);
  }
  if (message.files.length > 0) card.append(el(doc, "p", "cr-muted cr-small", `Files named in this message (not opened here): ${message.files.join(", ")}`));
  return card;
}

function taskCard(ctx: ViewContext, peer: string, task: TaskView): HTMLElement {
  const { doc } = ctx;
  const mine = task.side === "me";
  const card = el(doc, "article", "cr-card cr-task");
  const heading = el(doc, "header", "cr-card-head");
  heading.append(el(doc, "span", "cr-who", mine ? "Task your agent is working on" : `Task ${peer}'s agent is working on`));
  heading.append(el(doc, "span", `tc-badge cr-badge cr-state cr-state--${task.state.toLowerCase()}`, STATE_LABEL[task.state] ?? "Unknown state"));
  heading.append(timeElement(doc, task.timestamp ?? ulidTime(task.id), ctx.now()));
  card.append(heading);
  const ids = el(doc, "p", "cr-muted cr-small", `Task ${shortId(task.id)}${task.ask === "" ? "" : ` · ask ${task.ask}`}`);
  card.append(ids);
  if (task.note !== "") card.append(el(doc, "p", "cr-note", task.note));
  for (const artifact of task.artifacts) {
    const wrapper = el(doc, "section", "cr-artifact");
    const id = uid("cr-artifact");
    const name = el(doc, "h4", "cr-artifact-name", artifact.name === "" ? "Artifact" : artifact.name); name.id = id;
    wrapper.setAttribute("aria-labelledby", id);
    wrapper.append(name);
    body(ctx, wrapper, artifact.texts, artifact.name === "" ? "Artifact" : `Artifact: ${artifact.name}`);
    if (artifact.files.length > 0) wrapper.append(el(doc, "p", "cr-muted cr-small", `Files named (not opened here): ${artifact.files.join(", ")}`));
    card.append(wrapper);
  }
  return card;
}

function timelineCard(ctx: ViewContext, peer: string, item: TimelineItem): HTMLElement {
  return item.kind === "message" ? messageCard(ctx, peer, item.message) : taskCard(ctx, peer, item.task);
}

function loadFailure(error: unknown): string {
  const code = error instanceof StoreError ? error.code : "failed";
  if (code === "timeout" || code === "unreachable") return "We couldn't reach your TinyCloud. Try again.";
  if (code === "no-space") return "Your agent mailbox isn't set up yet. Set it up with the CLI or in Share, then come back.";
  if (code === "denied") return "This session isn't allowed to read your mailbox. Sign out and sign in again.";
  return "We couldn't load this thread. Try again.";
}

export function renderThread(ctx: ViewContext, summary: ThreadSummary | { peer: string; threadId: string; subject?: string }, back: () => void): HTMLElement {
  const { doc } = ctx;
  const section = el(doc, "section", "cr-screen");
  section.setAttribute("aria-labelledby", "cr-thread-title");
  const head = el(doc, "div", "cr-screen-head");
  const backButton = el(doc, "button", "button button-secondary tc-button tc-button--compact", "All threads"); backButton.type = "button";
  backButton.addEventListener("click", back);
  head.append(backButton);
  section.append(head);
  const title = el(doc, "h2", "cr-title", summary.subject ?? "Thread"); title.id = "cr-thread-title";
  title.tabIndex = -1;
  const meta = el(doc, "p", "cr-muted", `A conversation with ${summary.peer}. Your side and theirs, in order.`);
  section.append(title, meta);
  const content = el(doc, "div", "cr-thread-content");
  content.setAttribute("aria-busy", "true");
  content.append(el(doc, "p", "cr-muted", "Loading the conversation…"));
  section.append(content);

  void loadThread(ctx.store, summary).then((detail: ThreadDetail) => {
    if (!section.isConnected) return;
    content.replaceChildren();
    content.setAttribute("aria-busy", "false");
    if (detail.subject !== "(no subject)") title.textContent = detail.subject;
    if (detail.partial) content.append(status(doc, "warning", "Some of this thread couldn't be loaded, or it is longer than what is shown. Refresh to try again."));
    if (detail.timeline.length === 0) {
      const empty = el(doc, "div", "cr-empty");
      empty.append(el(doc, "p", "cr-empty-title", "Nothing in this thread yet."), el(doc, "p", "cr-muted", "Messages from the other side appear here once your agent's watcher has copied them in. That can take about a minute."));
      content.append(empty);
      return;
    }
    const list = el(doc, "div", "cr-timeline");
    list.setAttribute("role", "list");
    list.setAttribute("aria-label", "Messages and tasks, oldest first");
    for (const item of detail.timeline) {
      const row = el(doc, "div", "cr-timeline-item"); row.setAttribute("role", "listitem");
      row.append(timelineCard(ctx, summary.peer, item));
      list.append(row);
    }
    content.append(list);
  }, (error: unknown) => {
    content.replaceChildren();
    content.setAttribute("aria-busy", "false");
    const retry = el(doc, "button", "button button-secondary tc-button tc-button--compact", "Try again"); retry.type = "button";
    retry.addEventListener("click", () => ctx.openThread(summary));
    content.append(status(doc, "danger", loadFailure(error)), retry);
  });
  queueMicrotask(() => title.focus());
  return section;
}
