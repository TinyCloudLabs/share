/**
 * What the /courier page understands of the owner's own courier mailbox, and
 * the rules for turning it into something safe to show.
 *
 * Every string here may come from another party: a peer's agent wrote the
 * messages and tasks in `me/mirror/`, and an agent working on a peer's request
 * wrote `me/requests/`. Nothing is trusted: ids are validated against fixed
 * shapes, and unknown values fall back to a plain label. The page shows text as
 * text, never as markup (artifact bodies go through the markdown sanitiser).
 *
 * Two rules for text, kept apart on purpose:
 *  - what a person is asked to APPROVE (a request's verb, target, summary,
 *    action, reason and risk) is checked, never repaired: a value that is too
 *    long, not NFC, or holds a hidden character makes the request unreviewable,
 *    because a card that shows less than the hash covers could hide the part
 *    that matters;
 *  - every other label (subjects, names, notes) is only made safe to look at:
 *    capped, with hidden characters shown as visible escapes.
 */

import { VERBS, targetIsCanonical, type Verb } from "./target.js";

export { VERBS, type Verb };

export const EXT = "https://tinycloud.xyz/ext/courier/v0";
export const ULID = /^[0-9A-HJKMNP-TV-Z]{26}$/;
/** A peer handle as it appears in a key: a local nickname chosen at pairing. */
export const HANDLE = /^[A-Za-z0-9_-]{1,64}$/;

export const MAX_SUBJECT = 200;
export const MAX_LABEL = 120;
/** Caps for what an approval depends on. Over a cap the request is unreviewable: it is never shortened. */
export const MAX_ACTION = 2000;
export const MAX_REASON = 2000;
export const MAX_RISK = 2000;
/** The note is echoed to the agent, so the CLI refuses one that is over this or holds hidden text; the view refuses it before writing instead of repairing it. */
export const MAX_NOTE = 2000;
export const MAX_BODY = 256 * 1024;
export const MAX_ORDERS_BYTES = 64 * 1024;

// ------------------------------------------------------------------ text

/**
 * Characters a person cannot see or that change how neighbouring text is drawn:
 * control, format (zero-width, bidi, tag characters), private-use, unassigned,
 * lone surrogates, line and paragraph separators, every default-ignorable
 * (variation selectors, U+034F, Hangul and Khmer fillers), and any space other
 * than a plain one (no-break, em, ideographic: look-alikes for it), plus four
 * symbols that draw as a blank or nothing: U+2800, U+FFFC, U+1D159 and U+16FE4.
 */
const UNSAFE_CHAR = /[\p{Cc}\p{Cf}\p{Co}\p{Cn}\p{Cs}\p{Zl}\p{Zp}\p{Default_Ignorable_Code_Point}\u2800\uFFFC\u{1D159}\u{16FE4}]|(?! )\p{Zs}/u;
const UNSAFE_CHARS = /[\p{Cc}\p{Cf}\p{Co}\p{Cn}\p{Cs}\p{Zl}\p{Zp}\p{Default_Ignorable_Code_Point}\u2800\uFFFC\u{1D159}\u{16FE4}]|(?! )\p{Zs}/gu;
/** A long run of combining marks draws over the line above and below. */
const MARK_RUN = /\p{M}{4,}/u;
const MARK_RUNS = /\p{M}{4,}/gu;

function escapeHidden(text: string, keep: string = ""): string {
  return text
    .replace(UNSAFE_CHARS, (char) => (char === keep ? char : `⟦U+${char.codePointAt(0)!.toString(16).toUpperCase().padStart(4, "0")}⟧`))
    .replace(MARK_RUNS, "⟦many combining marks⟧");
}

/** One line of text for a label or a card field: capped, hidden characters escaped, line breaks flattened. */
export function oneLine(value: unknown, max: number): string {
  if (typeof value !== "string") return "";
  const flat = escapeHidden(value.replace(/[\n\r\t]+/g, " ")).trim();
  return flat.length > max ? `${flat.slice(0, max - 1)}…` : flat;
}

/** Several lines (a note, a quoted reason): capped, hidden characters escaped, line breaks kept. */
export function multiLine(value: unknown, max: number): string {
  if (typeof value !== "string") return "";
  const kept = escapeHidden(value.replace(/\r\n?/g, "\n"), "\n").trim();
  return kept.length > max ? `${kept.slice(0, max - 1)}…` : kept;
}

/**
 * `value` exactly as written when it is fit to approve, else undefined. Not repaired, not shortened: 1 to `max`
 * UTF-16 units, NFC, none of `UNSAFE_CHAR` (a `\n` is allowed only when `lines`), no long run of combining marks.
 * `trimmed` also refuses leading or trailing space.
 */
export function strictText(value: unknown, max: number, options: { readonly lines?: boolean; readonly trimmed?: boolean } = {}): string | undefined {
  if (typeof value !== "string" || value.length === 0 || value.length > max) return undefined;
  if (options.trimmed === true && value !== value.trim()) return undefined;
  if (UNSAFE_CHAR.test(options.lines === true ? value.replaceAll("\n", "") : value)) return undefined;
  if (MARK_RUN.test(value) || value !== value.normalize("NFC")) return undefined;
  return value;
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

/** Caps on the structured fields `courier request` writes (js-sdk packages/courier). A longer value is not shortened: the request is unreviewable. */
export const MAX_TARGET = 200;
export const MAX_SUMMARY = 200;

/** Quotation marks and their look-alikes (the CLI's DOUBLE_QUOTES), except the plain apostrophe U+0027 and U+2019: the summary is drawn between quotes, so one inside it could end the quote early. Refused, as the CLI refuses them. */
const QUOTES = /(?!['\u2019])[\p{Quotation_Mark}"\uFF02\u275D\u275E\u2760\u2E42\u{1F676}-\u{1F678}\u2033\u2036\u02BA\u05F4\u3003]/u;

/** WHAT approving would allow, from structured fields inside the hashed request. Still the agent's words: shown as plain text, never as markup. */
export interface RequestWhat {
  readonly verb: Verb;
  readonly target: string;
  readonly summary: string;
}

export function parseWhat(raw: Record<string, unknown>): RequestWhat | undefined {
  const verb = VERBS.find((candidate) => candidate === raw.verb);
  const target = strictText(raw.target, MAX_TARGET, { trimmed: true });
  const summary = strictText(raw.summary, MAX_SUMMARY, { trimmed: true });
  if (verb === undefined || target === undefined || summary === undefined) return undefined;
  if (QUOTES.test(summary) || !/^[\x20-\x7E]+$/.test(target) || !targetIsCanonical(verb, target)) return undefined;
  return { verb, target, summary };
}

/** Every string and key in `value` is fit to show (a single \n allowed): the CLI's approval sweeps the whole request, so the view does too. Nesting past the hash limit counts as not fit. */
export function sweepsClean(value: unknown, depth = 0): boolean {
  if (typeof value === "string") return !UNSAFE_CHAR.test(value.replaceAll("\n", "")) && !MARK_RUN.test(value) && value === value.normalize("NFC");
  if (value === null || typeof value !== "object") return true;
  if (depth >= 64) return false;
  const entries = Array.isArray(value) ? value.map((item): [string, unknown] => ["", item]) : Object.entries(value as Record<string, unknown>);
  return entries.every(([key, item]) => (key === "" || sweepsClean(key, depth + 1)) && sweepsClean(item, depth + 1));
}

/**
 * The keys `courier request` writes, and no others: what the hash covers is then what the card shows. The CLI's reader
 * (`courier approval`) requires the first set, allows the second when well-formed, and refuses any other key.
 */
const REQUIRED_KEYS = ["createdAt", "expiresAt", "id", "peer", "requestedBy", "status", "summary", "target", "taskId", "threadId", "verb"];
const OPTIONAL_KEYS = ["action", "reason", "risk"];
const REQUESTED_BY_KEYS = ["agent", "owner"] as const;
const MAX_DID = 300;

function sameKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const keys = Object.keys(value).sort();
  return keys.length === expected.length && keys.every((key, index) => key === expected[index]);
}

/** Every required key is there and no key outside the required and optional sets is. */
function keysAreRequestKeys(value: Record<string, unknown>): boolean {
  const keys = Object.keys(value);
  return REQUIRED_KEYS.every((key) => keys.includes(key)) && keys.every((key) => REQUIRED_KEYS.includes(key) || OPTIONAL_KEYS.includes(key));
}

/** Who filed the request: exactly `{owner, agent}`, both plain one-line text. */
function requestedByOf(value: unknown): { readonly owner: string; readonly agent: string } | undefined {
  if (!isRecord(value) || !sameKeys(value, REQUESTED_BY_KEYS)) return undefined;
  const owner = strictText(value.owner, MAX_DID, { trimmed: true });
  const agent = strictText(value.agent, MAX_DID, { trimmed: true });
  return owner === undefined || agent === undefined ? undefined : { owner, agent };
}

/** Why a request can be read here but not decided. */
export type RequestProblem = "fields" | "text" | "hash" | "task";

/** A request from one of the owner's own agents, as `courier request` wrote it. Peer-influenced text is kept apart from the structured fields. */
export interface RequestView {
  readonly id: string;
  readonly peer: string;
  readonly threadId: string;
  readonly taskId: string;
  /** Undefined when the request lacks a valid verb, target or summary. */
  readonly what: RequestWhat | undefined;
  /** Who filed it, when the field is exactly as the CLI writes it. */
  readonly requestedBy: { readonly owner: string; readonly agent: string } | undefined;
  /** The free text, exactly as written when `problem` is not "text"; otherwise an escaped, shortened look at it (never approvable). */
  readonly action: string;
  readonly reason: string;
  readonly risk: string;
  /**
   * Set when the request can be read here but not decided: "fields" (not exactly the request the CLI writes: a key
   * missing or extra, no valid verb, target and summary, a status other than pending), "text" (a quoted field is too
   * long or holds hidden characters), "hash" (it can't be fingerprinted) or "task" (the task it names isn't in the
   * owner's mailbox for that peer; set by the loader).
   */
  readonly problem: RequestProblem | undefined;
  readonly createdAt: number;
  readonly expiresAt: number;
  /** The parsed object exactly as stored: the approval's hash covers all of it. */
  readonly raw: unknown;
}

export function parseRequest(id: string, raw: unknown): RequestView | undefined {
  if (!isRecord(raw) || raw.id !== id || !ULID.test(id)) return undefined;
  const { peer, threadId, taskId } = raw;
  if (typeof peer !== "string" || !HANDLE.test(peer)) return undefined;
  if (typeof threadId !== "string" || !ULID.test(threadId)) return undefined;
  if (typeof taskId !== "string" || !ULID.test(taskId)) return undefined;
  const createdAt = parseTime(raw.createdAt);
  const expiresAt = parseTime(raw.expiresAt);
  if (createdAt === undefined || expiresAt === undefined) return undefined;
  const what = parseWhat(raw);
  const requestedBy = requestedByOf(raw.requestedBy);
  const shapeOk = what !== undefined && requestedBy !== undefined && keysAreRequestKeys(raw) && raw.status === "pending";
  // Optional free text: absent is fine, present must be well-formed (a present empty string is refused).
  const optional = (value: unknown, max: number): string | undefined => (value === undefined ? "" : strictText(value, max, { lines: true }));
  const action = optional(raw.action, MAX_ACTION);
  const reason = optional(raw.reason, MAX_REASON);
  const risk = optional(raw.risk, MAX_RISK);
  const textOk = action !== undefined && reason !== undefined && risk !== undefined && sweepsClean(raw);
  const problem: RequestProblem | undefined = !shapeOk ? "fields" : !textOk ? "text" : undefined;
  // Exact when fit to approve; otherwise only a safe look at what is there.
  const look = (value: unknown, exact: string | undefined): string => exact ?? (value === undefined ? "" : multiLine(typeof value === "string" ? value : "(not text)", 600));
  return { id, peer, threadId, taskId, what, requestedBy, problem, createdAt, expiresAt, raw, action: look(raw.action, action), reason: look(raw.reason, reason), risk: look(raw.risk, risk) };
}

/** True when the card may offer Approve and Deny. */
export function isDecidable(request: RequestView): boolean {
  return request.what !== undefined && request.problem === undefined;
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

/** True when `note` can be saved as typed: empty, or text the CLI accepts (same rules as the request's free text). */
export function noteFitsToSave(note: string): boolean {
  return note === "" || strictText(note, MAX_NOTE, { lines: true }) !== undefined;
}

/** `note` is written exactly as typed; the caller has checked `noteFitsToSave` first. */
export function approvalFile(request: RequestView, requestHash: string, decision: Decision, note: string, now: number): ApprovalFile {
  return { requestId: request.id, requestHash, decision, note, decidedAt: new Date(now).toISOString() };
}

export type RequestStanding = "pending" | "expired" | "approved" | "denied";

export function requestStanding(request: RequestView, approval: ApprovalView | undefined, now: number): RequestStanding {
  if (approval !== undefined) return approval.decision;
  return now >= request.expiresAt ? "expired" : "pending";
}
