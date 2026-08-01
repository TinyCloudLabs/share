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

/** IDataVaultService already encrypts values in the browser's network Vault. */
export class EncryptedSenderShareRecordStorage implements SenderShareRecordStorage {
  constructor(private readonly vault: IDataVaultService) {}

  async put(record: SenderShareRecord): Promise<void> {
    const result = await this.vault.put(recordKey(record.shareId), record, { metadata: { "x-sender-history-version": "2", "x-sender-history-kind": "share" } });
    if (!result.ok) throw new Error("sender-history-save-failed");
  }

  async list(): Promise<readonly SenderShareRecord[]> {
    const vault = this.vault as unknown as {
      listPage?: (options: { prefix: string; removePrefix: boolean; limit: number; cursor?: string }) => Promise<{ ok: boolean; data?: { keys: string[]; truncated: boolean; nextCursor?: string } }>;
      list?: (options: { prefix: string; removePrefix: boolean; limit: number }) => Promise<{ ok: boolean; data?: string[] }>;
    };
    const listed = vault.listPage !== undefined
      ? await vault.listPage({ prefix: SENDER_HISTORY_PREFIX, removePrefix: false, limit: 1000 })
      : await vault.list?.({ prefix: SENDER_HISTORY_PREFIX, removePrefix: false, limit: 1000 });
    if (listed === undefined || !listed.ok || listed.data === undefined) throw new Error("sender-history-list-failed");
    const keys = Array.isArray(listed.data) ? listed.data : listed.data.keys;
    const records: SenderShareRecord[] = [];
    for (const key of keys) {
      if (shareIdFromKey(key) === undefined) continue;
      const result = await this.vault.get<VaultValue>(key);
      if (!result.ok) continue;
      const value = unwrap(result.data);
      if (isRecord(value)) records.push(value);
    }
    return records;
  }

  async get(shareId: string): Promise<SenderShareRecord | undefined> {
    const result = await this.vault.get<VaultValue>(recordKey(shareId));
    if (!result.ok) return undefined;
    const value = unwrap(result.data);
    return isRecord(value) ? value : undefined;
  }

  async delete(shareId: string): Promise<void> {
    const result = await this.vault.delete(recordKey(shareId));
    if (!result.ok) throw new Error("sender-history-remove-failed");
  }
}

function itemState(record: SenderShareRecord, now: number): "ready" | "expired" | "revoked" {
  if (record.revokedAt !== undefined) return "revoked";
  return Date.parse(record.expiresAt) <= now ? "expired" : "ready";
}

function viewFor(record: SenderShareRecord, views: readonly ShareHistoryView[]): ShareHistoryView {
  return views.find((candidate) => candidate.shareId === record.shareId) ?? { shareId: record.shareId, target: "bearer", expiresAt: record.expiresAt, revoked: record.revokedAt !== undefined };
}

/** Converts the canonical publication receipt to the canonical history record. */
export function createSenderHistoryRecord(result: PublishedShare): SenderShareRecord { return historyRecordForPublishedShare(result); }

/** Explicit import path for a link the sender already possesses. */
export function importSenderHistoryRecord(url: string, now = new Date()): SenderShareRecord {
  const parsed = new URL(url);
  const filename = parsed.pathname === "/s/inline" ? undefined : parsed.pathname.split("/").at(-1);
  return {
    shareId: `import-${crypto.randomUUID().replaceAll("-", "")}`,
    target: { origin: parsed.origin, nodeAudience: "", spaceId: "" },
    resource: { kind: "exact", path: filename ?? "inline" },
    actions: ["tinycloud.kv/get"],
    recipientMatcher: { kind: "bearer" },
    targetKind: "bearer",
    registeredAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000).toISOString(),
    link: url,
    ...(filename === undefined ? {} : { filename }),
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
    const records = [...await this.records.list()].sort((left, right) => Date.parse(right.registeredAt) - Date.parse(left.registeredAt));
    const views = await listShares(this.records);
    const offset = cursor === undefined ? 0 : Number.parseInt(cursor, 10);
    if (!Number.isSafeInteger(offset) || offset < 0) throw new Error("sender-history-cursor-invalid");
    const selected = records.slice(offset, offset + limit);
    const items: SenderHistoryItem[] = selected.map((record): SenderHistoryItem => ({ record, view: viewFor(record, views), key: recordKey(record.shareId), state: itemState(record, this.now()) }));
    const nextOffset = offset + selected.length;
    return { items, truncated: nextOffset < records.length, ...(nextOffset < records.length ? { nextCursor: String(nextOffset) } : {}) };
  }

  static keyFor(record: SenderShareRecord): string { return recordKey(record.shareId); }
}
