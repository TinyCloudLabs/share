/**
 * What the /courier page understands of the owner's own courier mailbox, and
 * the rules for turning it into something safe to show.
 *
 * Every string here may come from another party: a peer's agent wrote the
 * messages and tasks in `me/mirror/`, and an agent working on a peer's request
 * wrote `me/requests/`. Nothing is trusted: ids are validated against fixed
 * shapes, text is length-capped and stripped of control and bidirectional
 * characters, and unknown values fall back to a plain label. The page shows the
 * result as text, never as markup (artifact bodies go through the markdown
 * sanitiser, see `thread-view.ts`).
 */

export const EXT = "https://tinycloud.xyz/ext/courier/v0";
export const ULID = /^[0-9A-HJKMNP-TV-Z]{26}$/;
/** A peer handle as it appears in a key: a local nickname chosen at pairing. */
export const HANDLE = /^[a-z0-9][a-z0-9_-]{0,31}$/;

export const MAX_SUBJECT = 200;
export const MAX_LABEL = 120;
export const MAX_ACTION = 600;
export const MAX_REASON = 2000;
export const MAX_RISK = 600;
export const MAX_NOTE = 1000;
export const MAX_BODY = 256 * 1024;
export const MAX_ORDERS_BYTES = 64 * 1024;

// ------------------------------------------------------------------ text

/** Control, format, line-separator and bidirectional characters: shown as a visible escape, never acted on. */
const HIDDEN = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F\u00AD\u061C\u115F\u1160\u180E\u200B-\u200F\u2028-\u202F\u205F-\u206F\u3164\uFEFF\uFFA0\uFFF9-\uFFFC]/g;
const LINE_BREAKS = /[\n\r\t]+/g;

function escapeHidden(text: string): string {
  return text.replace(HIDDEN, (char) => `⟦U+${char.charCodeAt(0).toString(16).toUpperCase().padStart(4, "0")}⟧`);
}

/** One line of text for a label or a card field: capped, hidden characters escaped, line breaks flattened. */
export function oneLine(value: unknown, max: number): string {
  if (typeof value !== "string") return "";
  const flat = escapeHidden(value.replace(LINE_BREAKS, " ")).trim();
  return flat.length > max ? `${flat.slice(0, max - 1)}…` : flat;
}

/** Several lines (a note, a reason): capped, hidden characters escaped, line breaks kept. */
export function multiLine(value: unknown, max: number): string {
  if (typeof value !== "string") return "";
  const kept = escapeHidden(value.replace(/\r\n?/g, "\n")).trim();
  return kept.length > max ? `${kept.slice(0, max - 1)}…` : kept;
}

/** Message and artifact text for the markdown renderer: only length-capped (the sanitiser owns the rest). */
export function bodyText(value: unknown): string {
  return typeof value === "string" ? (value.length > MAX_BODY ? value.slice(0, MAX_BODY) : value) : "";
}

// ------------------------------------------------------------------ time

const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/** The millisecond timestamp a ULID begins with; undefined for anything that is not one. */
export function ulidTime(id: string): number | undefined {
  if (!ULID.test(id)) return undefined;
  let time = 0;
  for (let index = 0; index < 10; index += 1) time = time * 32 + CROCKFORD.indexOf(id[index]!);
  return Number.isSafeInteger(time) ? time : undefined;
}

export function parseTime(value: unknown): number | undefined {
  if (typeof value !== "string") return undefined;
  const time = Date.parse(value);
  return Number.isFinite(time) ? time : undefined;
}

// ------------------------------------------------------------------ keys

export const COURIER_ROOT = "xyz.tinycloud.courier/";

export type ThreadSide = "me" | "peer";
export type ThreadPart = "meta" | "msg" | "task";

export type ParsedKey =
  | { readonly kind: "thread"; readonly side: ThreadSide; readonly peer: string; readonly threadId: string; readonly part: ThreadPart; readonly id: string }
  | { readonly kind: "request"; readonly id: string }
  | { readonly kind: "approval"; readonly id: string }
  | { readonly kind: "orders"; readonly peer: string };

/** Only the keys the page reads: anything else under the prefix (receipts, pairing, state, files) is ignored. */
export function parseKey(key: string): ParsedKey | undefined {
  if (!key.startsWith(COURIER_ROOT)) return undefined;
  const parts = key.slice(COURIER_ROOT.length).split("/");
  const thread = (side: ThreadSide, peer: string | undefined, rest: string[]): ParsedKey | undefined => {
    if (peer === undefined || !HANDLE.test(peer) || rest[0] !== "threads") return undefined;
    const threadId = rest[1];
    if (threadId === undefined || !ULID.test(threadId)) return undefined;
    if (rest.length === 3 && rest[2] === "meta.json") return { kind: "thread", side, peer, threadId, part: "meta", id: threadId };
    if (rest.length === 4 && (rest[2] === "msg" || rest[2] === "task") && rest[3]!.endsWith(".json")) {
      const id = rest[3]!.slice(0, -".json".length);
      return ULID.test(id) ? { kind: "thread", side, peer, threadId, part: rest[2], id } : undefined;
    }
    return undefined;
  };
  if (parts[0] === "to") return thread("me", parts[1], parts.slice(2));
  if (parts[0] === "me" && parts[1] === "mirror") return thread("peer", parts[2], parts.slice(3));
  if (parts[0] === "me" && parts.length === 3) {
    const name = parts[2]!;
    if (parts[1] === "requests" && name.endsWith(".json") && ULID.test(name.slice(0, -5))) return { kind: "request", id: name.slice(0, -5) };
    if (parts[1] === "approvals" && name.endsWith(".json") && ULID.test(name.slice(0, -5))) return { kind: "approval", id: name.slice(0, -5) };
    if (parts[1] === "orders" && name.endsWith(".md") && HANDLE.test(name.slice(0, -3))) return { kind: "orders", peer: name.slice(0, -3) };
  }
  return undefined;
}

export const keys = {
  request: (id: string): string => `${COURIER_ROOT}me/requests/${id}.json`,
  approval: (id: string): string => `${COURIER_ROOT}me/approvals/${id}.json`,
  orders: (peer: string): string => `${COURIER_ROOT}me/orders/${peer}.md`,
  thread: (side: ThreadSide, peer: string, threadId: string, part: ThreadPart, id: string): string => {
    const base = side === "me" ? `${COURIER_ROOT}to/${peer}/threads/${threadId}` : `${COURIER_ROOT}me/mirror/${peer}/threads/${threadId}`;
    return part === "meta" ? `${base}/meta.json` : `${base}/${part}/${id}.json`;
  },
};

// ------------------------------------------------------------------ index

export interface ThreadRef {
  readonly peer: string;
  readonly threadId: string;
}

export interface ThreadIndexEntry extends ThreadRef {
  /** Keys by side. A thread is both sides' files taken together. */
  readonly meta: Record<ThreadSide, string | undefined>;
  readonly messages: { readonly side: ThreadSide; readonly id: string }[];
  readonly tasks: { readonly side: ThreadSide; readonly id: string }[];
}

export interface MailboxIndex {
  readonly threads: ThreadIndexEntry[];
  readonly requestIds: string[];
  readonly approvalIds: string[];
  readonly orderPeers: string[];
  /** True when the node's listing was cut short: some keys are not shown. */
  readonly truncated: boolean;
}

export function buildIndex(allKeys: readonly string[], truncated: boolean): MailboxIndex {
  const threads: Record<string, ThreadIndexEntry> = {};
  const requestIds = new Set<string>();
  const approvalIds = new Set<string>();
  const orderPeers = new Set<string>();
  for (const key of allKeys) {
    const parsed = parseKey(key);
    if (parsed === undefined) continue;
    if (parsed.kind === "request") requestIds.add(parsed.id);
    else if (parsed.kind === "approval") approvalIds.add(parsed.id);
    else if (parsed.kind === "orders") orderPeers.add(parsed.peer);
    else {
      const slot = `${parsed.peer}/${parsed.threadId}`;
      const entry = (threads[slot] ??= { peer: parsed.peer, threadId: parsed.threadId, meta: { me: undefined, peer: undefined }, messages: [], tasks: [] });
      if (parsed.part === "meta") entry.meta[parsed.side] = key;
      else if (parsed.part === "msg") entry.messages.push({ side: parsed.side, id: parsed.id });
      else entry.tasks.push({ side: parsed.side, id: parsed.id });
    }
  }
  return {
    threads: Object.values(threads),
    requestIds: [...requestIds].sort(),
    approvalIds: [...approvalIds].sort(),
    orderPeers: [...orderPeers].sort(),
    truncated,
  };
}

// ------------------------------------------------------------------ messages and tasks

export const INTENTS = ["request", "ask", "answer", "update", "inform"] as const;
export type Intent = (typeof INTENTS)[number] | "unknown";

export const TASK_STATES = [
  "SUBMITTED", "WORKING", "INPUT_REQUIRED", "AUTH_REQUIRED", "COMPLETED", "FAILED", "CANCELED", "REJECTED",
] as const;
export type TaskState = (typeof TASK_STATES)[number] | "UNKNOWN";
const TERMINAL: readonly TaskState[] = ["COMPLETED", "FAILED", "CANCELED", "REJECTED"];

export function isOpenTask(state: TaskState): boolean {
  return !TERMINAL.includes(state);
}

/** The one guard for this module's untrusted JSON; fields stay `unknown` and are checked where used. */
export const isRecord = (value: unknown): value is Record<string, unknown> => typeof value === "object" && value !== null && !Array.isArray(value);
const asArray = (value: unknown): unknown[] => (Array.isArray(value) ? value : []);

export interface TextPart {
  readonly text: string;
  readonly markdown: boolean;
}

function textParts(value: unknown): { texts: TextPart[]; files: string[] } {
  const texts: TextPart[] = [];
  const files: string[] = [];
  for (const part of asArray(value).slice(0, 20)) {
    if (!isRecord(part)) continue;
    if (typeof part.text === "string") {
      texts.push({ text: bodyText(part.text), markdown: part.mediaType === undefined || part.mediaType === "text/markdown" || part.mediaType === "text/plain" });
    } else if (typeof part.url === "string" || typeof part.name === "string") {
      // A file reference is shown by name only: the page never follows a link a peer's text carries.
      files.push(oneLine(part.name ?? part.url, MAX_LABEL));
    }
  }
  return { texts, files };
}

export interface MessageView {
  readonly id: string;
  readonly side: ThreadSide;
  readonly intent: Intent;
  readonly from: string;
  readonly texts: TextPart[];
  readonly files: string[];
  readonly asks: { id: string; title: string }[];
  readonly constraints: string[];
  readonly taskRefs: string[];
}

export function parseMessage(side: ThreadSide, id: string, raw: unknown): MessageView | undefined {
  if (!isRecord(raw) || raw.messageId !== id) return undefined;
  const ext = isRecord(raw.metadata) && isRecord(raw.metadata[EXT]) ? raw.metadata[EXT] : {};
  const intent = INTENTS.find((candidate) => candidate === ext.intent) ?? "unknown";
  const from = isRecord(ext.from) ? oneLine(ext.from.label, MAX_LABEL) : "";
  const { texts, files } = textParts(raw.parts);
  return {
    id,
    side,
    intent,
    from,
    texts,
    files,
    asks: asArray(ext.asks).slice(0, 20).flatMap((ask) => (isRecord(ask) ? [{ id: oneLine(ask.id, 32), title: oneLine(ask.title, MAX_SUBJECT) }] : [])),
    constraints: asArray(ext.constraints).slice(0, 20).flatMap((item) => (typeof item === "string" ? [oneLine(item, MAX_SUBJECT)] : [])),
    taskRefs: asArray(raw.referenceTaskIds).filter((item): item is string => typeof item === "string" && ULID.test(item)).slice(0, 20),
  };
}

export interface ArtifactView {
  readonly id: string;
  readonly name: string;
  readonly texts: TextPart[];
  readonly files: string[];
}

export interface TaskView {
  readonly id: string;
  readonly side: ThreadSide;
  readonly state: TaskState;
  readonly timestamp: number | undefined;
  readonly note: string;
  readonly ask: string;
  readonly artifacts: ArtifactView[];
}

export function parseTask(side: ThreadSide, id: string, raw: unknown): TaskView | undefined {
  if (!isRecord(raw) || raw.id !== id || !isRecord(raw.status)) return undefined;
  const stateText = typeof raw.status.state === "string" ? raw.status.state.replace(/^TASK_STATE_/, "") : "";
  const state = TASK_STATES.find((candidate) => candidate === stateText) ?? "UNKNOWN";
  const note = isRecord(raw.status.message) ? textParts(raw.status.message.parts).texts.map((part) => part.text).join("\n") : "";
  const ext = isRecord(raw.metadata) && isRecord(raw.metadata[EXT]) ? raw.metadata[EXT] : {};
  const artifacts = asArray(raw.artifacts).slice(0, 20).flatMap((artifact, index): ArtifactView[] => {
    if (!isRecord(artifact)) return [];
    const { texts, files } = textParts(artifact.parts);
    return [{ id: oneLine(artifact.artifactId, 64) || `artifact-${index + 1}`, name: oneLine(artifact.name ?? artifact.artifactId, MAX_LABEL), texts, files }];
  });
  return { id, side, state, timestamp: parseTime(raw.status.timestamp), note: multiLine(note, MAX_NOTE), ask: oneLine(ext.ask, 32), artifacts };
}

export interface ThreadMetaView {
  readonly subject: string;
  readonly startedBy: ThreadSide;
  readonly createdAt: number | undefined;
}

export function parseMeta(side: ThreadSide, raw: unknown): ThreadMetaView | undefined {
  if (!isRecord(raw)) return undefined;
  const subject = oneLine(raw.subject, MAX_SUBJECT);
  return { subject: subject === "" ? "(no subject)" : subject, startedBy: side, createdAt: parseTime(raw.createdAt) };
}

// ------------------------------------------------------------------ requests and approvals

/** A request from one of the owner's own agents, as `courier request` wrote it. Peer-influenced text is kept apart from the structured fields. */
export interface RequestView {
  readonly id: string;
  readonly peer: string;
  readonly threadId: string;
  readonly taskId: string;
  readonly action: string;
  readonly reason: string;
  readonly risk: string;
  readonly createdAt: number;
  readonly expiresAt: number;
  /** The parsed object exactly as stored: the approval's hash covers all of it. */
  readonly raw: unknown;
}

export function parseRequest(id: string, raw: unknown): RequestView | undefined {
  if (!isRecord(raw) || raw.id !== id) return undefined;
  const { peer, threadId, taskId } = raw;
  if (typeof peer !== "string" || !HANDLE.test(peer)) return undefined;
  if (typeof threadId !== "string" || !ULID.test(threadId)) return undefined;
  if (typeof taskId !== "string" || !ULID.test(taskId)) return undefined;
  const createdAt = parseTime(raw.createdAt);
  const expiresAt = parseTime(raw.expiresAt);
  if (createdAt === undefined || expiresAt === undefined) return undefined;
  const action = multiLine(raw.action, MAX_ACTION);
  if (action === "") return undefined;
  return { id, peer, threadId, taskId, action, reason: multiLine(raw.reason, MAX_REASON), risk: multiLine(raw.risk, MAX_RISK), createdAt, expiresAt, raw };
}

export type Decision = "approved" | "denied";

export interface ApprovalView {
  readonly requestId: string;
  readonly decision: Decision;
  readonly note: string;
  readonly decidedAt: number | undefined;
}

export function parseApproval(id: string, raw: unknown): ApprovalView | undefined {
  if (!isRecord(raw) || raw.requestId !== id) return undefined;
  if (raw.decision !== "approved" && raw.decision !== "denied") return undefined;
  return { requestId: id, decision: raw.decision, note: multiLine(raw.note, MAX_NOTE), decidedAt: parseTime(raw.decidedAt) };
}

/** The file a decision is written as. `decidedAt` is this device's clock: it is informational and never trusted. */
export interface ApprovalFile {
  readonly requestId: string;
  readonly requestHash: string;
  readonly decision: Decision;
  readonly note: string;
  readonly decidedAt: string;
}

export function approvalFile(request: RequestView, requestHash: string, decision: Decision, note: string, now: number): ApprovalFile {
  return { requestId: request.id, requestHash, decision, note: multiLine(note, MAX_NOTE), decidedAt: new Date(now).toISOString() };
}

export type RequestStanding = "pending" | "expired" | "approved" | "denied";

export function requestStanding(request: RequestView, approval: ApprovalView | undefined, now: number): RequestStanding {
  if (approval !== undefined) return approval.decision;
  return now >= request.expiresAt ? "expired" : "pending";
}
