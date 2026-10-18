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
  | { readonly state: "ready" | "expired" | "revoked"; readonly key: string; readonly record: SenderHistoryDisplayRecord; readonly view: ShareHistoryView }
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
/** Re-reads of one record when a local write lands while it is being read. */
const MAX_RACED_READS = 3;

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
 * The only thing kept in memory between calls is an index of share id to
 * `registeredAt`, which is what ordering needs. Records themselves (which carry
 * the bearer link and Policy/v3 delivery material) are never retained here:
 * `readRows` reads the ones being displayed, live, and the caller owns them.
 * Because every displayed row is read fresh, its revoke state is whatever the
 * vault holds, including a revoke made from another tab or the CLI.
 *
 * Local writes go through `put`/`delete`. A read that overlaps a write to the
 * same record is repeated after the write completes, so a revoke is never
 * shown as active because a read started before it finished.
 */
export class EncryptedSenderShareRecordStorage implements SenderShareRecordStorage {
  /** shareId -> registeredAt (ms), in listing order. */
  private readonly index = new Map<string, number>();
  private indexed = false;
  private inflight: Promise<ReadonlyMap<string, SenderShareRecord>> | undefined;
  /** Bumped at the start and end of every local write to a record. */
  private epoch = 0;
  private readonly touched = new Map<string, number>();
  private readonly writing = new Map<string, Promise<void>>();

  constructor(private readonly vault: IDataVaultService) {}

  async put(record: SenderShareRecord): Promise<void> {
    await this.write(record.shareId, async () => {
      const result = await this.vault.put(recordKey(record.shareId), record, { metadata: { "x-sender-history-version": "2", "x-sender-history-kind": "share" } });
      if (!result.ok) throw new Error("sender-history-save-failed");
      this.index.set(record.shareId, Date.parse(record.registeredAt));
    });
  }

  /** Every readable record, read fresh in listing order. Not cached. */
  async list(): Promise<readonly SenderShareRecord[]> {
    return this.readRows(await this.listShareIds());
  }

  async get(shareId: string): Promise<SenderShareRecord | undefined> {
    return this.readCurrent(shareId);
  }

  async delete(shareId: string): Promise<void> {
    await this.write(shareId, async () => {
      const result = await this.vault.delete(recordKey(shareId));
      if (!result.ok) throw new Error("sender-history-remove-failed");
      this.index.delete(shareId);
    });
  }

  /**
   * Re-lists the keys (one request per 1000) and reads the records the index
   * does not have yet, keeping only their `registeredAt`. Returns the records
   * read during this pass so the caller can show them without a second read;
   * they are not retained here.
   */
  refreshIndex(): Promise<ReadonlyMap<string, SenderShareRecord>> {
    this.inflight ??= this.refresh().finally(() => { this.inflight = undefined; });
    return this.inflight;
  }

  hasIndex(): boolean { return this.indexed; }

  /** Share ids with their `registeredAt`, in listing order. */
  indexEntries(): readonly (readonly [string, number])[] { return [...this.index]; }

  /**
   * Reads the given records fresh, at most SENDER_HISTORY_FETCH_CONCURRENCY at
   * a time, in input order. Unreadable or malformed entries are skipped;
   * thrown errors reject. `known` supplies records read moments ago.
   */
  async readRows(shareIds: readonly string[], known?: ReadonlyMap<string, SenderShareRecord>): Promise<SenderShareRecord[]> {
    const rows = await mapBounded(shareIds, SENDER_HISTORY_FETCH_CONCURRENCY, async (id) => known?.get(id) ?? this.readCurrent(id));
    return rows.filter((row): row is SenderShareRecord => row !== undefined);
  }

  private touch(shareId: string): void { this.touched.set(shareId, ++this.epoch); }
  private raced(shareId: string, started: number): boolean { return (this.touched.get(shareId) ?? 0) > started; }

  private async write(shareId: string, operation: () => Promise<void>): Promise<void> {
    this.touch(shareId);
    const run = operation().finally(() => this.touch(shareId));
    const settled = run.then(() => undefined, () => undefined);
    this.writing.set(shareId, settled);
    try { await run; } finally { if (this.writing.get(shareId) === settled) this.writing.delete(shareId); }
  }

  /** One vault GET and decrypt. Unreadable or malformed entries are undefined; thrown errors propagate. */
  private async read(shareId: string): Promise<SenderShareRecord | undefined> {
    const result = await this.vault.get<VaultValue>(recordKey(shareId));
    if (!result.ok) return undefined;
    const value = unwrap(result.data);
    return isRecord(value) ? value : undefined;
  }

  /** Reads after any in-flight local write to this record, and again if one began meanwhile. */
  private async readCurrent(shareId: string): Promise<SenderShareRecord | undefined> {
    for (let attempt = 1; ; attempt += 1) {
      await this.writing.get(shareId);
      const started = this.epoch;
      const record = await this.read(shareId);
      if (!this.raced(shareId, started) || attempt >= MAX_RACED_READS) return record;
    }
  }

  private async listShareIds(): Promise<string[]> {
    const vault = this.vault as unknown as ListingVault;
    const ids = new Set<string>();
    const seenCursors = new Set<string>();
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
      // A truncated page whose cursor is missing or already used cannot advance; fail rather than loop or return a partial list as complete.
      if (next === undefined || seenCursors.has(next)) throw new Error("sender-history-list-failed");
      seenCursors.add(next);
      cursor = next;
    }
    return [...ids];
  }

  private async refresh(): Promise<ReadonlyMap<string, SenderShareRecord>> {
    const passStart = this.epoch;
    const ids = await this.listShareIds();
    const missing = ids.filter((id) => !this.index.has(id));
    const fetched = new Map<string, SenderShareRecord>();
    await mapBounded(missing, SENDER_HISTORY_FETCH_CONCURRENCY, async (id) => {
      const record = await this.readCurrent(id);
      if (record !== undefined) fetched.set(id, record);
    });
    const listed = new Set(ids);
    const next = new Map<string, number>();
    for (const id of ids) {
      const registeredAt = fetched.has(id) ? Date.parse((fetched.get(id) as SenderShareRecord).registeredAt) : this.index.get(id);
      if (registeredAt !== undefined) next.set(id, registeredAt);
    }
    // Keep records written locally during this pass even if the listing predates them.
    for (const [id, registeredAt] of this.index) if (!listed.has(id) && this.raced(id, passStart)) next.set(id, registeredAt);
    this.index.clear();
    for (const [id, registeredAt] of next) this.index.set(id, registeredAt);
    this.indexed = true;
    return fetched;
  }
}

function itemState(record: SenderShareRecord, now: number): "ready" | "expired" | "revoked" {
  if (record.revokedAt !== undefined) return "revoked";
  return Date.parse(record.expiresAt) <= now ? "expired" : "ready";
}

function viewFor(record: SenderShareRecord): ShareHistoryView {
  return { shareId: record.shareId, target: "bearer", expiresAt: record.expiresAt, revoked: record.revokedAt !== undefined };
}

/**
 * What a library row needs. The bearer link, Policy/v3 delivery material and
 * delivered mailboxes are left out: Open, Copy and Revoke read the full record
 * from the vault when clicked.
 */
export type SenderHistoryDisplayRecord = Omit<SenderShareRecord, "link" | "deliveryMaterial" | "deliveredRecipients">;

function displayRecord(record: SenderShareRecord): SenderHistoryDisplayRecord {
  const { link: _link, deliveryMaterial: _deliveryMaterial, deliveredRecipients: _deliveredRecipients, ...display } = record;
  return display;
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
    // A first page re-lists the keys; later pages reuse that index so "Load more" does not list again.
    const justRead = cursor === undefined || !this.records.hasIndex() ? await this.records.refreshIndex() : undefined;
    const ordered = [...this.records.indexEntries()].sort((left, right) => right[1] - left[1]);
    const selectedIds = ordered.slice(offset, offset + limit).map(([id]) => id);
    // Only the rows shown are read (fresh, so a revoke made elsewhere shows). Redact them from the records already in hand.
    const selected = await this.records.readRows(selectedIds, justRead);
    const views = new Map((await listShares(readOnlyStorage(selected))).map((view) => [view.shareId, view]));
    const items: SenderHistoryItem[] = selected.map((record): SenderHistoryItem => ({ record: displayRecord(record), view: views.get(record.shareId) ?? viewFor(record), key: recordKey(record.shareId), state: itemState(record, this.now()) }));
    const nextOffset = offset + selectedIds.length;
    return { items, truncated: nextOffset < ordered.length, ...(nextOffset < ordered.length ? { nextCursor: String(nextOffset) } : {}) };
  }

  static keyFor(record: SenderShareRecord): string { return recordKey(record.shareId); }
}
