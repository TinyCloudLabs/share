import {
  historyRecordForPublishedShare,
  listShares,
  showShare,
  type PublishedShare,
  type SenderShareRecord,
  type SenderShareRecordStorage,
  type ShareHistoryView,
} from "@tinycloud/share-sdk";
import type { IDataVaultService } from "@tinycloud/web-sdk";

/** Browser persistence adapter for the canonical SDK sender record. */
export type SenderHistoryRecord = SenderShareRecord;
export const SENDER_HISTORY_PREFIX = "sender-history/v2/records/";

export type SenderHistoryItem =
  | { readonly state: "ready" | "expired" | "revoked"; readonly key: string; readonly record: SenderShareRecord; readonly view: ShareHistoryView }
  | { readonly state: "needs-attention"; readonly key: string; readonly reason: "corrupt" | "undecryptable" | "unsupported" };

export interface SenderHistoryPage {
  readonly items: readonly SenderHistoryItem[];
  readonly truncated: boolean;
  readonly nextCursor?: string;
}

type VaultValue = { readonly value?: unknown } | unknown;

function recordKey(shareId: string): string { return `${SENDER_HISTORY_PREFIX}${shareId}`; }

function shareIdFromKey(value: string): string | undefined {
  if (!value.startsWith(SENDER_HISTORY_PREFIX)) return undefined;
  const shareId = value.slice(SENDER_HISTORY_PREFIX.length);
  return shareId.length > 0 && shareId.length <= 512 ? shareId : undefined;
}

function shareIdFromListedValue(value: string): string | undefined {
  const qualified = shareIdFromKey(value);
  if (qualified !== undefined) return qualified;
  return value.length > 0 && value.length <= 512 && /^[A-Za-z0-9_-]+$/.test(value) ? value : undefined;
}

function unwrap(value: VaultValue): unknown {
  if (value !== null && typeof value === "object" && Object.hasOwn(value, "value")) return (value as { readonly value: unknown }).value;
  return value;
}

function isRecord(value: unknown): value is SenderShareRecord {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const candidate = value as Record<string, unknown>;
  return typeof candidate.shareId === "string" && candidate.shareId.length > 0
    && typeof candidate.registeredAt === "string" && typeof candidate.expiresAt === "string"
    && typeof candidate.target === "object" && candidate.target !== null
    && typeof candidate.resource === "object" && candidate.resource !== null
    && Array.isArray(candidate.actions)
    && typeof candidate.recipientMatcher === "object" && candidate.recipientMatcher !== null;
}

/**
 * Records fetched at once. Each record costs a vault GET plus a network
 * decrypt, and browsers cap HTTP/1.1 connections at 6 per origin, so more
 * in flight only queues in the browser.
 */
export const SENDER_HISTORY_FETCH_CONCURRENCY = 6;
/** Keys requested per listing page; the listing follows `nextCursor` past it. */
const LIST_PAGE_LIMIT = 1000;

type VaultListPage = { ok: boolean; data?: string[] | { keys: string[]; truncated: boolean; nextCursor?: string } };
type ListingVault = {
  listPage?: (options: { prefix: string; removePrefix: boolean; limit: number; cursor?: string }) => Promise<VaultListPage>;
  list?: (options: { prefix: string; removePrefix: boolean; limit: number }) => Promise<VaultListPage>;
};

/**
 * Runs `task` over `items` with at most `limit` in flight. Results keep the
 * input order. The first rejection rejects the whole call, and no new item
 * starts after it, matching the former serial loop where one thrown error
 * aborted the pass.
 */
async function mapBounded<T, R>(items: readonly T[], limit: number, task: (item: T) => Promise<R>): Promise<R[]> {
  const results = new Array<R>(items.length);
  let next = 0;
  let failed = false;
  const worker = async (): Promise<void> => {
    while (!failed && next < items.length) {
      const index = next++;
      try { results[index] = await task(items[index] as T); } catch (caught) { failed = true; throw caught; }
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return results;
}

/**
 * IDataVaultService already encrypts values in the browser's network Vault.
 *
 * Decrypted records are kept in memory for the life of the instance (one
 * signed-in session) so paging, revoke, import and retry do not repeat the
 * per-record GET and decrypt. Every write goes through `put`/`delete`, so the
 * cache is updated in the same call that changes the vault: a revoke is
 * visible on the next read. `list()` re-reads the key listing (one request per
 * 1000 keys), fetches only records it does not hold, and drops records whose
 * key is gone, so shares added or removed elsewhere appear on the next fresh
 * load. A record changed elsewhere (for example revoked from another tab)
 * keeps its cached state until the page is reloaded.
 */
export class EncryptedSenderShareRecordStorage implements SenderShareRecordStorage {
  private readonly cache = new Map<string, SenderShareRecord>();
  /** Share ids in listing order; undefined until the first listing completes. */
  private order: string[] | undefined;
  private inflight: Promise<void> | undefined;
  /** Bumped at the start and end of every local write; lets a pass discard a read that raced one. */
  private epoch = 0;
  private readonly touched = new Map<string, number>();

  constructor(private readonly vault: IDataVaultService) {}

  async put(record: SenderShareRecord): Promise<void> {
    this.touch(record.shareId);
    const result = await this.vault.put(recordKey(record.shareId), record, { metadata: { "x-sender-history-version": "2", "x-sender-history-kind": "share" } });
    if (!result.ok) throw new Error("sender-history-save-failed");
    this.touch(record.shareId);
    this.cache.set(record.shareId, record);
    if (this.order !== undefined && !this.order.includes(record.shareId)) this.order.push(record.shareId);
  }

  /** Fresh listing: follows the cursor, fetches only records not yet cached. */
  async list(): Promise<readonly SenderShareRecord[]> {
    this.inflight ??= this.refresh().finally(() => { this.inflight = undefined; });
    await this.inflight;
    return this.snapshot();
  }

  /** The records from the last listing with local writes applied; lists first if none yet. */
  async listCached(): Promise<readonly SenderShareRecord[]> {
    return this.order === undefined ? this.list() : this.snapshot();
  }

  async get(shareId: string): Promise<SenderShareRecord | undefined> {
    const cached = this.cache.get(shareId);
    if (cached !== undefined) return cached;
    const started = this.epoch;
    const record = await this.read(shareId);
    if (record !== undefined && !this.raced(shareId, started)) this.cache.set(shareId, record);
    return record;
  }

  async delete(shareId: string): Promise<void> {
    this.touch(shareId);
    const result = await this.vault.delete(recordKey(shareId));
    if (!result.ok) throw new Error("sender-history-remove-failed");
    this.touch(shareId);
    this.cache.delete(shareId);
    if (this.order !== undefined) this.order = this.order.filter((id) => id !== shareId);
  }

  private touch(shareId: string): void { this.touched.set(shareId, ++this.epoch); }
  private raced(shareId: string, started: number): boolean { return (this.touched.get(shareId) ?? 0) > started; }

  private snapshot(): SenderShareRecord[] {
    const records: SenderShareRecord[] = [];
    for (const id of this.order ?? []) { const record = this.cache.get(id); if (record !== undefined) records.push(record); }
    return records;
  }

  /** One vault GET and decrypt. Unreadable or malformed entries are skipped (undefined); thrown errors propagate. */
  private async read(shareId: string): Promise<SenderShareRecord | undefined> {
    const result = await this.vault.get<VaultValue>(recordKey(shareId));
    if (!result.ok) return undefined;
    const value = unwrap(result.data);
    return isRecord(value) ? value : undefined;
  }

  private async listShareIds(): Promise<string[]> {
    const vault = this.vault as unknown as ListingVault;
    const ids = new Set<string>();
    let cursor: string | undefined;
    for (;;) {
      const options = { prefix: SENDER_HISTORY_PREFIX, removePrefix: true, limit: LIST_PAGE_LIMIT };
      const listed = vault.listPage !== undefined
        ? await vault.listPage(cursor === undefined ? options : { ...options, cursor })
        : await vault.list?.(options);
      if (listed === undefined || !listed.ok || listed.data === undefined) throw new Error("sender-history-list-failed");
      const keys = Array.isArray(listed.data) ? listed.data : listed.data.keys;
      for (const key of keys) {
        const shareId = shareIdFromListedValue(key);
        if (shareId !== undefined) ids.add(shareId);
      }
      if (Array.isArray(listed.data) || !listed.data.truncated) break;
      const next = listed.data.nextCursor;
      // A truncated page with no new cursor cannot advance; fail rather than loop or return a partial list as complete.
      if (next === undefined || next === cursor) throw new Error("sender-history-list-failed");
      cursor = next;
    }
    return [...ids];
  }

  private async refresh(): Promise<void> {
    const passStart = this.epoch;
    const ids = await this.listShareIds();
    const missing = ids.filter((id) => !this.cache.has(id));
    const fetched = await mapBounded(missing, SENDER_HISTORY_FETCH_CONCURRENCY, async (id) => {
      const started = this.epoch;
      return { id, started, record: await this.read(id) };
    });
    // A read that raced a local write may hold the pre-write value; drop it. The record is picked up on the next fresh list.
    for (const { id, started, record } of fetched) if (record !== undefined && !this.raced(id, started)) this.cache.set(id, record);
    const listed = new Set(ids);
    // Keep records written locally during this pass even if the listing predates them.
    for (const id of [...this.cache.keys()]) if (!listed.has(id) && !this.raced(id, passStart)) this.cache.delete(id);
    this.order = [...ids.filter((id) => this.cache.has(id)), ...[...this.cache.keys()].filter((id) => !listed.has(id))];
  }
}

function itemState(record: SenderShareRecord, now: number): "ready" | "expired" | "revoked" {
  if (record.revokedAt !== undefined) return "revoked";
  return Date.parse(record.expiresAt) <= now ? "expired" : "ready";
}

function viewFor(record: SenderShareRecord): ShareHistoryView {
  return { shareId: record.shareId, target: "bearer", expiresAt: record.expiresAt, revoked: record.revokedAt !== undefined };
}

/** Lets the SDK's canonical redaction run over records already in hand, without another vault pass. */
function readOnlyStorage(records: readonly SenderShareRecord[]): SenderShareRecordStorage {
  const refuse = async (): Promise<never> => { throw new Error("sender-history-read-only"); };
  return { put: refuse, delete: refuse, list: async () => records, get: async (shareId) => records.find((record) => record.shareId === shareId) };
}

/** Converts the canonical publication receipt to the canonical history record. */
export function createSenderHistoryRecord(result: PublishedShare): SenderShareRecord { return historyRecordForPublishedShare(result); }

/** Explicit import path for a link the sender already possesses. */
export function importSenderHistoryRecord(url: string, now = new Date()): SenderShareRecord {
  const parsed = new URL(url);
  const fragment = new URLSearchParams(parsed.hash.slice(1));
  if (parsed.pathname !== "/viewer" || parsed.search !== "" || fragment.size !== 1 || !fragment.get("tc1")) throw new Error("sender-history-link-invalid");
  return {
    shareId: `import-${crypto.randomUUID().replaceAll("-", "")}`,
    target: { origin: parsed.origin, nodeAudience: "", spaceId: "" },
    resource: { kind: "exact", path: "native-share" },
    actions: ["tinycloud.kv/get"],
    recipientMatcher: { kind: "bearer" },
    targetKind: "bearer",
    registeredAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000).toISOString(),
    link: url,
  };
}

export class SenderHistoryRepository {
  readonly records: EncryptedSenderShareRecordStorage;

  constructor(vault: IDataVaultService, private readonly now: () => number = Date.now) { this.records = new EncryptedSenderShareRecordStorage(vault); }

  async save(record: SenderShareRecord): Promise<void> {
    if (!isRecord(record)) throw new Error("sender-history-record-invalid");
    await this.records.put(record);
  }

  async remove(keyOrShareId: string): Promise<void> {
    const shareId = keyOrShareId.startsWith(SENDER_HISTORY_PREFIX) ? shareIdFromKey(keyOrShareId) : keyOrShareId;
    if (shareId === undefined) throw new Error("sender-history-key-invalid");
    await this.records.delete(shareId);
  }

  /** Persists a node-confirmed revocation. Node calls are owned by revokeShare. */
  async markRevoked(record: SenderShareRecord): Promise<void> { await this.save({ ...record, revokedAt: new Date(this.now()).toISOString() }); }

  async show(shareId: string, revealLink = false): Promise<ShareHistoryView> {
    const record = await this.records.get(shareId);
    if (record === undefined) throw new Error("share-not-found");
    return showShare({ storage: this.records, shareId, revealLink, ...(revealLink && record.link !== undefined ? { link: record.link } : {}) });
  }

  async page(cursor?: string, limit = 25): Promise<SenderHistoryPage> {
    const offset = cursor === undefined ? 0 : Number.parseInt(cursor, 10);
    if (!Number.isSafeInteger(offset) || offset < 0) throw new Error("sender-history-cursor-invalid");
    // A first page is a fresh listing; later pages reuse its snapshot so offsets stay stable and "Load more" costs no requests.
    const listed = cursor === undefined ? await this.records.list() : await this.records.listCached();
    const records = [...listed].sort((left, right) => Date.parse(right.registeredAt) - Date.parse(left.registeredAt));
    const selected = records.slice(offset, offset + limit);
    // Redact only the rows on this page, from the records already read.
    const views = new Map((await listShares(readOnlyStorage(selected))).map((view) => [view.shareId, view]));
    const items: SenderHistoryItem[] = selected.map((record): SenderHistoryItem => ({ record, view: views.get(record.shareId) ?? viewFor(record), key: recordKey(record.shareId), state: itemState(record, this.now()) }));
    const nextOffset = offset + selected.length;
    return { items, truncated: nextOffset < records.length, ...(nextOffset < records.length ? { nextCursor: String(nextOffset) } : {}) };
  }

  static keyFor(record: SenderShareRecord): string { return recordKey(record.shareId); }
}
