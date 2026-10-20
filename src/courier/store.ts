/**
 * The page's only door to the owner's courier mailbox.
 *
 * Reads: list the whole courier prefix once, then read single objects. Every
 * call has a timeout and a response-size cap, the whole load has one budget,
 * and at most a few reads run at once. Writes: exactly two kinds, an approval
 * decision (create-only) and a standing-orders file (compare-and-swap on the
 * etag it was read at). Nothing is cached outside this tab's memory.
 */
import type { IKVService } from "@tinycloud/sdk-services";
import { APPROVALS_PREFIX, ORDERS_PREFIX } from "./scope.js";
import { COURIER_ROOT, MAX_BODY, MAX_ORDERS_BYTES, keys, type ApprovalFile } from "./model.js";

export type StoreFailure = "no-space" | "unreachable" | "denied" | "too-large" | "timeout" | "changed" | "failed";

/** Never carries the key, the value or the node's message: only a code the page can word. */
export class StoreError extends Error {
  readonly code: StoreFailure;
  constructor(code: StoreFailure) {
    super(`courier-store-${code}`);
    this.name = "StoreError";
    this.code = code;
  }
}

export interface Listing {
  readonly keys: string[];
  readonly truncated: boolean;
}

export interface OrdersFile {
  readonly text: string;
  /** What `writeOrders` must hand back: the version this text was read at. */
  readonly etag: string | undefined;
}

export interface CourierStore {
  list(): Promise<Listing>;
  /** The parsed JSON at `key`; undefined when there is none. Load fan-out shares the listing budget; user reads have their own. */
  readJson(key: string, options?: { readonly loadBudget: true }): Promise<unknown>;
  readOrders(peer: string): Promise<OrdersFile | undefined>;
  /** Create-only: "exists" when a decision for this request was already written. */
  createApproval(file: ApprovalFile): Promise<"created" | "exists">;
  /** `etag` is the version read (undefined = there was no file). "changed" when the file moved on since. */
  writeOrders(peer: string, text: string, etag: string | undefined): Promise<void>;
}

export type CourierKv = Pick<IKVService, "get" | "put" | "list">;

export const CALL_TIMEOUT_MS = 8_000;
export const LOAD_BUDGET_MS = 30_000;
export const MAX_CONCURRENT_READS = 6;
/** A listing past this many keys is cut off: the page says so rather than render a partial mailbox as complete. */
export const MAX_KEYS = 5_000;
const LIST_PAGE = 1_000;
const MAX_LIST_PAGES = 6;
/** A JSON object this size is not a courier file. */
const MAX_JSON_BYTES = MAX_BODY + 16 * 1024;

interface Failure {
  readonly code?: unknown;
  readonly message?: unknown;
  readonly meta?: { readonly status?: unknown };
}

function failureOf(error: Failure | undefined): StoreFailure {
  const code = String(error?.code ?? "");
  const status = String(error?.meta?.status ?? "");
  const message = String(error?.message ?? "");
  if (code === "KV_RESPONSE_TOO_LARGE") return "too-large";
  if (/space not found/i.test(message)) return "no-space";
  if (status === "401" || status === "403" || /UNAUTHORIZED|FORBIDDEN|AUTH/i.test(code)) return "denied";
  if (/TIMEOUT|ABORT/i.test(code)) return "timeout";
  if (/NETWORK|FETCH|UNREACHABLE/i.test(code)) return "unreachable";
  return "failed";
}

const isNotFound = (error: Failure | undefined): boolean => String(error?.code ?? "") === "KV_NOT_FOUND" || String(error?.meta?.status ?? "") === "404";
const isPreconditionFailed = (error: Failure | undefined): boolean => String(error?.code ?? "") === "KV_PRECONDITION_FAILED" || String(error?.meta?.status ?? "") === "412";

export interface KvStoreOptions {
  readonly callTimeoutMs?: number;
  readonly budgetMs?: number;
  readonly now?: () => number;
}

/** Wraps a space-scoped KV service. `kv` must be the owner's courier space; the page has no other. */
export function createKvStore(kv: CourierKv, options: KvStoreOptions = {}): CourierStore {
  const callTimeout = options.callTimeoutMs ?? CALL_TIMEOUT_MS;
  const budget = options.budgetMs ?? LOAD_BUDGET_MS;
  const now = options.now ?? Date.now;
  let budgetStart = now();
  let active = 0;
  const waiting: (() => void)[] = [];

  /** Runs `call` with a per-call deadline that also respects what is left of the overall budget; a hung call is abandoned, not awaited. */
  async function bounded<T>(call: (signal: AbortSignal) => Promise<T>, startedAt = now()): Promise<T> {
    while (active >= MAX_CONCURRENT_READS) await new Promise<void>((resume) => waiting.push(resume));
    active += 1;
    const left = budget - (now() - startedAt);
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      if (left <= 0) throw new StoreError("timeout");
      const deadline = new Promise<never>((_resolve, reject) => {
        timer = setTimeout(() => { controller.abort(); reject(new StoreError("timeout")); }, Math.min(callTimeout, left));
      });
      return await Promise.race([call(controller.signal), deadline]);
    } catch (error) {
      if (error instanceof StoreError) throw error;
      throw new StoreError("unreachable");
    } finally {
      clearTimeout(timer);
      controller.abort();
      active -= 1;
      waiting.shift()?.();
    }
  }

  const common = (signal: AbortSignal) => ({ prefix: "", timeout: callTimeout, signal });

  return {
    async list() {
      budgetStart = now();
      const found = new Set<string>();
      let truncated = false;
      let cursor: string | undefined;
      for (let page = 0; page < MAX_LIST_PAGES; page += 1) {
        const result = await bounded((signal) => kv.list({ ...common(signal), prefix: COURIER_ROOT, limit: LIST_PAGE, ...(cursor === undefined ? {} : { cursor }) }), budgetStart);
        if (!result.ok) {
          // An absent space reads as a node error, not an empty list.
          throw new StoreError(failureOf(result.error));
        }
        const before = found.size;
        for (const key of result.data.keys) found.add(key);
        truncated = result.data.truncated === true;
        // Production list cursors do not always advance (TC-719): a page with nothing new ends the walk.
        if (!truncated || result.data.nextCursor === undefined || found.size === before || found.size >= MAX_KEYS) break;
        cursor = result.data.nextCursor;
      }
      return { keys: [...found].slice(0, MAX_KEYS), truncated: truncated || found.size > MAX_KEYS };
    },

    async readJson(key, readOptions) {
      const result = await bounded((signal) => kv.get<unknown>(key, { ...common(signal), maxResponseBytes: MAX_JSON_BYTES }), readOptions?.loadBudget === true ? budgetStart : now());
      if (!result.ok) {
        if (isNotFound(result.error)) return undefined;
        throw new StoreError(failureOf(result.error));
      }
      const value = result.data.data;
      if (typeof value !== "string") return value;
      try { return JSON.parse(value) as unknown; } catch { return undefined; }
    },

    async readOrders(peer) {
      const result = await bounded((signal) => kv.get<unknown>(keys.orders(peer), { ...common(signal), maxResponseBytes: MAX_ORDERS_BYTES }));
      if (!result.ok) {
        if (isNotFound(result.error)) return undefined;
        throw new StoreError(failureOf(result.error));
      }
      const value = result.data.data;
      const text = typeof value === "string" ? value : value instanceof Uint8Array ? new TextDecoder().decode(value) : undefined;
      if (text === undefined) throw new StoreError("failed");
      const etag = result.data.headers.etag;
      return { text, etag: typeof etag === "string" ? etag : undefined };
    },

    async createApproval(file) {
      const key = keys.approval(file.requestId);
      if (!key.startsWith(APPROVALS_PREFIX)) throw new StoreError("failed");
      const result = await bounded((signal) => kv.put(key, JSON.stringify(file), { ...common(signal), contentType: "application/json", ifNoneMatch: "*" }));
      if (result.ok) return "created";
      if (isPreconditionFailed(result.error)) return "exists";
      throw new StoreError(failureOf(result.error));
    },

    async writeOrders(peer, text, etag) {
      const key = keys.orders(peer);
      if (!key.startsWith(ORDERS_PREFIX)) throw new StoreError("failed");
      if (new TextEncoder().encode(text).byteLength > MAX_ORDERS_BYTES) throw new StoreError("too-large");
      const condition = etag === undefined ? { ifNoneMatch: "*" as const } : { ifMatch: etag };
      const result = await bounded((signal) => kv.put(key, text, { ...common(signal), contentType: "text/markdown; charset=utf-8", ...condition }));
      if (result.ok) return;
      if (isPreconditionFailed(result.error)) throw new StoreError("changed");
      throw new StoreError(failureOf(result.error));
    },
  };
}
