/**
 * Turns the store's raw files into what the screens show. Reads only; the two
 * writes (a decision, the orders file) go straight to the store from the
 * screens that own them.
 */
import { requestHash } from "./canonical.js";
import {
  buildIndex,
  isDecidable,
  isOpenTask,
  keys,
  parseApproval,
  parseMessage,
  parseMeta,
  parseRequest,
  parseTask,
  requestStanding,
  ulidTime,
  type ApprovalView,
  type MessageView,
  type RequestStanding,
  type RequestView,
  type TaskView,
  type ThreadIndexEntry,
  type ThreadRef,
  type ThreadSide,
} from "./model.js";
import { StoreError, type CourierStore } from "./store.js";

/** Newest first; older threads and requests are not read. The page says so. */
export const MAX_THREADS = 200;
export const MAX_REQUESTS = 100;
export const MAX_THREAD_ITEMS = 300;

export interface ThreadSummary extends ThreadRef {
  readonly subject: string;
  readonly lastActivity: number | undefined;
  readonly openTasks: number;
  /** Pending approval requests that belong to this thread. */
  readonly needsYou: number;
}

export interface RequestCard {
  readonly request: RequestView;
  /** SHA-256 of the request exactly as read; the decision carries it. Empty when the request can't be hashed (then it isn't decidable). */
  readonly hash: string;
  readonly standing: RequestStanding;
  readonly approval: ApprovalView | undefined;
  /** The subject of the thread the request is about, when that thread is in the mailbox. */
  readonly subject: string | undefined;
}

export interface Overview {
  readonly threads: ThreadSummary[];
  readonly requests: RequestCard[];
  /** Peers a person can write standing orders for: every handle seen in the mailbox. */
  readonly peers: string[];
  /** Requests that are not valid courier requests: shown as a count, never as a card. */
  readonly unreadable: number;
  /** Some files did not load, or the mailbox was longer than what is shown. */
  readonly partial: boolean;
}

async function tryRead(store: CourierStore, key: string, failures: { count: number }): Promise<unknown> {
  try {
    return await store.readJson(key);
  } catch (error) {
    // A mailbox that cannot be reached at all is the caller's problem; one file that will not load is a gap in the list.
    if (error instanceof StoreError && (error.code === "no-space" || error.code === "denied")) throw error;
    failures.count += 1;
    return undefined;
  }
}

function newestFirst<T>(items: readonly T[], idOf: (item: T) => string, limit: number): T[] {
  return [...items].sort((a, b) => (idOf(a) < idOf(b) ? 1 : idOf(a) > idOf(b) ? -1 : 0)).slice(0, limit);
}

function lastMessageTime(entry: ThreadIndexEntry): number | undefined {
  let latest: number | undefined;
  for (const message of entry.messages) {
    const time = ulidTime(message.id);
    if (time !== undefined && (latest === undefined || time > latest)) latest = time;
  }
  return latest ?? ulidTime(entry.threadId);
}

export async function loadOverview(store: CourierStore, now: number): Promise<Overview> {
  const listing = await store.list();
  const index = buildIndex(listing.keys, listing.truncated);
  const failures = { count: 0 };

  const entries = newestFirst(index.threads, (entry) => entry.threadId, MAX_THREADS);
  const requestIds = newestFirst(index.requestIds, (id) => id, MAX_REQUESTS);
  const approvalIds = new Set(index.approvalIds);

  const cards = await Promise.all(requestIds.map(async (id): Promise<RequestCard | "unreadable"> => {
    const request = parseRequest(id, await tryRead(store, keys.request(id), failures));
    if (request === undefined) return "unreadable";
    const approval = approvalIds.has(id) ? parseApproval(id, await tryRead(store, keys.approval(id), failures)) : undefined;
    // One request that can't be hashed (a number that isn't finite, nesting too deep) is shown as unreviewable; the others are unaffected.
    let hash = "";
    let shown = request;
    try {
      hash = await requestHash(request.raw);
    } catch {
      shown = { ...request, problem: "hash" };
    }
    // A decision file that does not parse is not a decision: the request stays open and the agent side refuses it too.
    return { request: shown, hash, standing: requestStanding(request, approval, now), approval, subject: undefined };
  }));
  const requests = cards.filter((card): card is RequestCard => card !== "unreadable");

  const summaries = await Promise.all(entries.map(async (entry): Promise<ThreadSummary> => {
    const metaSide: ThreadSide = entry.meta.me !== undefined ? "me" : "peer";
    const metaKey = entry.meta[metaSide];
    const meta = metaKey === undefined ? undefined : parseMeta(metaSide, await tryRead(store, metaKey, failures));
    let lastActivity = lastMessageTime(entry);
    let openTasks = 0;
    await Promise.all(newestFirst(entry.tasks, (task) => task.id, MAX_THREAD_ITEMS).map(async (task) => {
      const view = parseTask(task.side, task.id, await tryRead(store, keys.thread(task.side, entry.peer, entry.threadId, "task", task.id), failures));
      if (view === undefined) return;
      if (isOpenTask(view.state)) openTasks += 1;
      if (view.timestamp !== undefined && (lastActivity === undefined || view.timestamp > lastActivity)) lastActivity = view.timestamp;
    }));
    // Only a request the person can decide counts: one that can't be reviewed is listed but not actionable.
    const needsYou = requests.filter((card) => card.standing === "pending" && isDecidable(card.request) && card.request.peer === entry.peer && card.request.threadId === entry.threadId).length;
    return { peer: entry.peer, threadId: entry.threadId, subject: meta?.subject ?? "(no subject)", lastActivity, openTasks, needsYou };
  }));
  summaries.sort((a, b) => (b.lastActivity ?? 0) - (a.lastActivity ?? 0));

  const subjectOf = (card: RequestCard): string | undefined => summaries.find((thread) => thread.peer === card.request.peer && thread.threadId === card.request.threadId)?.subject;
  const peers = [...new Set([...index.threads.map((entry) => entry.peer), ...index.orderPeers, ...requests.map((card) => card.request.peer)])].sort();
  return {
    threads: summaries,
    requests: requests.map((card) => ({ ...card, subject: subjectOf(card) })),
    peers,
    unreadable: cards.length - requests.length,
    partial: failures.count > 0 || index.truncated || index.threads.length > MAX_THREADS || index.requestIds.length > MAX_REQUESTS,
  };
}

export type TimelineItem =
  | { readonly kind: "message"; readonly id: string; readonly message: MessageView }
  | { readonly kind: "task"; readonly id: string; readonly task: TaskView };

export interface ThreadDetail {
  readonly peer: string;
  readonly threadId: string;
  readonly subject: string;
  readonly timeline: TimelineItem[];
  readonly partial: boolean;
}

/** The thread as both sides' files taken together, ordered by ULID. Own files win a duplicate id. */
export async function loadThread(store: CourierStore, ref: ThreadRef): Promise<ThreadDetail> {
  const listing = await store.list();
  const index = buildIndex(listing.keys, listing.truncated);
  const entry = index.threads.find((candidate) => candidate.peer === ref.peer && candidate.threadId === ref.threadId);
  if (entry === undefined) return { ...ref, subject: "(no subject)", timeline: [], partial: index.truncated };
  const failures = { count: 0 };
  const metaSide: ThreadSide = entry.meta.me !== undefined ? "me" : "peer";
  const metaKey = entry.meta[metaSide];
  const meta = metaKey === undefined ? undefined : parseMeta(metaSide, await tryRead(store, metaKey, failures));

  const messageIds = new Map<string, ThreadSide>();
  for (const message of entry.messages) if (!messageIds.has(message.id) || message.side === "me") messageIds.set(message.id, message.side);
  const taskIds = new Map<string, ThreadSide>();
  for (const task of entry.tasks) if (!taskIds.has(task.id) || task.side === "me") taskIds.set(task.id, task.side);

  const wantedMessages = newestFirst([...messageIds], ([id]) => id, MAX_THREAD_ITEMS);
  const wantedTasks = newestFirst([...taskIds], ([id]) => id, MAX_THREAD_ITEMS);
  const timeline: TimelineItem[] = [];
  await Promise.all([
    ...wantedMessages.map(async ([id, side]) => {
      const message = parseMessage(side, id, await tryRead(store, keys.thread(side, ref.peer, ref.threadId, "msg", id), failures));
      if (message !== undefined) timeline.push({ kind: "message", id, message });
      else failures.count += 1;
    }),
    ...wantedTasks.map(async ([id, side]) => {
      const task = parseTask(side, id, await tryRead(store, keys.thread(side, ref.peer, ref.threadId, "task", id), failures));
      if (task !== undefined) timeline.push({ kind: "task", id, task });
      else failures.count += 1;
    }),
  ]);
  timeline.sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : a.kind === "message" ? -1 : 1));
  return {
    ...ref,
    subject: meta?.subject ?? "(no subject)",
    timeline,
    partial: failures.count > 0 || index.truncated || messageIds.size > MAX_THREAD_ITEMS || taskIds.size > MAX_THREAD_ITEMS,
  };
}
