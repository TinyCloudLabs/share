import { canonicalize } from "@tinycloud/share-envelope";
import type { IDataVaultService } from "@tinycloud/web-sdk";

export const SENDER_HISTORY_PREFIX = "sender-history/v1/entries/";
const MAX_URL_BYTES = 64 * 1024;
const MAX_RECORD_BYTES = 128 * 1024;
const ID_RE = /^[A-Za-z0-9_-]{16,80}$/;
const DIGEST_RE = /^[A-Za-z0-9_-]{43}$/;
const COMPACT_HASH_RE = /^#k=[A-Za-z0-9_-]{43}(?:&i=[A-Za-z0-9_-]{22}(?:&c=[A-Za-z0-9_-]{43})?)?$/;
const INLINE_HASH_RE = /^#v=2&p=[A-Za-z0-9_-]+$/;
const MAX_INLINE_HASH_BYTES = 700_000;

export type SenderHistoryRecipient =
  | { readonly kind: "bearer" }
  | { readonly kind: "exactEmail"; readonly value: string }
  | { readonly kind: "emailDomain"; readonly value: string };

export interface SenderHistoryRecord {
  readonly type: "TinyCloudShareSenderHistory";
  readonly version: 1;
  readonly id: string;
  readonly url: string;
  readonly cid: string;
  readonly format: "compact" | "inline";
  readonly createdAt: string;
  readonly expiresAt: string;
  readonly name: string;
  readonly mediaType: string;
  readonly sourceKind: "upload" | "author" | "kv";
  readonly recipient: SenderHistoryRecipient;
  readonly actions: readonly ("read" | "list" | "edit")[];
  readonly urlDigest: string;
}

export type SenderHistoryItem =
  | { readonly state: "ready" | "expired"; readonly key: string; readonly record: SenderHistoryRecord }
  | { readonly state: "needs-attention"; readonly key: string; readonly reason: "corrupt" | "undecryptable" | "unsupported" };

export interface SenderHistoryPage {
  readonly items: readonly SenderHistoryItem[];
  readonly truncated: boolean;
  readonly nextCursor?: string;
}

function fail(): never {
  throw new TypeError("Sender history entry is invalid.");
}

function stringField(value: unknown, max: number): string {
  if (typeof value !== "string" || value.length === 0 || value.length > max) return fail();
  return value;
}

function canonicalTimestamp(value: unknown): string {
  const text = stringField(value, 30);
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(text) || !Number.isFinite(Date.parse(text))) return fail();
  return text;
}

function validateUrl(value: unknown): string {
  const url = stringField(value, MAX_URL_BYTES);
  if (new TextEncoder().encode(url).byteLength > MAX_URL_BYTES) return fail();
  let parsed: URL;
  try { parsed = new URL(url); } catch { return fail(); }
  if (parsed.protocol !== "https:") return fail();
  if (parsed.username || parsed.password || parsed.search !== "" || parsed.hash === "") return fail();
  if (parsed.pathname === "/s/inline") {
    if (!INLINE_HASH_RE.test(parsed.hash) || new TextEncoder().encode(parsed.hash).byteLength > MAX_INLINE_HASH_BYTES) return fail();
  } else if (!/^\/s\/[a-z2-7]+$/.test(parsed.pathname) || !COMPACT_HASH_RE.test(parsed.hash)) {
    return fail();
  }
  return url;
}

export function validateSenderHistoryRecord(value: unknown): SenderHistoryRecord {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return fail();
  const input = value as Record<string, unknown>;
  const expected = ["type", "version", "id", "url", "cid", "format", "createdAt", "expiresAt", "name", "mediaType", "sourceKind", "recipient", "actions", "urlDigest"];
  if (Object.keys(input).some((key) => !expected.includes(key)) || expected.some((key) => !Object.hasOwn(input, key))) return fail();
  if (input.type !== "TinyCloudShareSenderHistory" || input.version !== 1 || typeof input.id !== "string" || !ID_RE.test(input.id)) return fail();
  const url = validateUrl(input.url);
  if (typeof input.cid !== "string" || input.cid.length === 0 || input.cid.length > 200) return fail();
  if (input.format !== "compact" && input.format !== "inline") return fail();
  const createdAt = canonicalTimestamp(input.createdAt);
  const expiresAt = canonicalTimestamp(input.expiresAt);
  if (Date.parse(expiresAt) <= Date.parse(createdAt)) return fail();
  const name = stringField(input.name, 240);
  const mediaType = stringField(input.mediaType, 240);
  if (input.sourceKind !== "upload" && input.sourceKind !== "author" && input.sourceKind !== "kv") return fail();
  if (typeof input.recipient !== "object" || input.recipient === null || Array.isArray(input.recipient)) return fail();
  const recipient = input.recipient as Record<string, unknown>;
  if (recipient.kind === "bearer") {
    if (Object.keys(recipient).length !== 1) return fail();
  } else if (recipient.kind === "exactEmail" || recipient.kind === "emailDomain") {
    if (Object.keys(recipient).some((key) => key !== "kind" && key !== "value") || typeof recipient.value !== "string" || recipient.value.length === 0 || recipient.value.length > 320) return fail();
  } else return fail();
  if (!Array.isArray(input.actions) || input.actions.length === 0 || input.actions.some((action) => action !== "read" && action !== "list" && action !== "edit") || new Set(input.actions).size !== input.actions.length) return fail();
  if (typeof input.urlDigest !== "string" || !DIGEST_RE.test(input.urlDigest)) return fail();
  const record = { ...input, url, createdAt, expiresAt, name, mediaType, recipient: { ...recipient }, actions: [...input.actions], id: input.id, cid: input.cid, format: input.format, sourceKind: input.sourceKind, urlDigest: input.urlDigest } as unknown as SenderHistoryRecord;
  if (new TextEncoder().encode(canonicalize(record)).byteLength > MAX_RECORD_BYTES) return fail();
  return record;
}

async function digestUrl(url: string): Promise<string> {
  const bytes = new TextEncoder().encode(url);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  let binary = "";
  for (const byte of new Uint8Array(digest)) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function keyFor(record: SenderHistoryRecord): string {
  const inverse = String(Math.max(0, 9_999_999_999_999 - Date.parse(record.createdAt))).padStart(13, "0");
  return `${SENDER_HISTORY_PREFIX}${inverse}/${record.id}`;
}

function fullHistoryKey(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  if (value.startsWith(SENDER_HISTORY_PREFIX)) return value;
  // Some deployed Vault list implementations honor the prefix by returning
  // relative keys even when removePrefix is false. Reattach only the closed
  // sender-history key shape before reading; unrelated keys remain corrupt.
  return /^\d{13}\/[A-Za-z0-9_-]{16,80}$/.test(value) ? `${SENDER_HISTORY_PREFIX}${value}` : undefined;
}

export async function createSenderHistoryRecord(input: Omit<SenderHistoryRecord, "type" | "version" | "urlDigest">): Promise<SenderHistoryRecord> {
  const record = validateSenderHistoryRecord({ ...input, type: "TinyCloudShareSenderHistory", version: 1, urlDigest: await digestUrl(input.url) });
  return record;
}

export class SenderHistoryRepository {
  constructor(private readonly vault: IDataVaultService, private readonly now: () => number = Date.now) {}

  async save(record: SenderHistoryRecord): Promise<void> {
    const valid = validateSenderHistoryRecord(record);
    const result = await this.vault.put(keyFor(valid), valid, { metadata: { "x-sender-history-version": "1", "x-sender-history-kind": "share" } });
    if (!result.ok) throw new Error("sender-history-save-failed");
  }

  async remove(key: string): Promise<void> {
    if (!key.startsWith(SENDER_HISTORY_PREFIX) || key.length > SENDER_HISTORY_PREFIX.length + 100) throw new Error("sender-history-key-invalid");
    const result = await this.vault.delete(key);
    if (!result.ok) throw new Error("sender-history-remove-failed");
  }

  async page(cursor?: string, limit = 25): Promise<SenderHistoryPage> {
    const vault = this.vault as unknown as {
      listPage?: (options: { prefix: string; removePrefix: boolean; limit: number; cursor?: string }) => Promise<{ ok: boolean; data?: { keys: string[]; truncated: boolean; nextCursor?: string } }>;
      list?: (options: { prefix: string; removePrefix: boolean; limit: number }) => Promise<{ ok: boolean; data?: string[] }>;
    };
    const listed = vault.listPage !== undefined
      ? await vault.listPage({ prefix: SENDER_HISTORY_PREFIX, removePrefix: false, limit, ...(cursor === undefined ? {} : { cursor }) })
      : await vault.list?.({ prefix: SENDER_HISTORY_PREFIX, removePrefix: false, limit });
    if (listed === undefined || !listed.ok || listed.data === undefined) throw new Error("sender-history-list-failed");
    const listedPage = Array.isArray(listed.data)
      ? { keys: listed.data, truncated: false as const, nextCursor: undefined }
      : listed.data;
    const items: SenderHistoryItem[] = [];
    const seenDigests = new Set<string>();
    for (const rawKey of listedPage.keys) {
      const key = fullHistoryKey(rawKey);
      if (key === undefined) {
        items.push({ key: "invalid", state: "needs-attention", reason: "corrupt" });
        continue;
      }
      const result = await this.vault.get<unknown>(key);
      if (!result.ok) {
        items.push({ key, state: "needs-attention", reason: "undecryptable" });
        continue;
      }
      try {
        // The current Web SDK returns a VaultEntry wrapper, while older
        // production bundles returned the decrypted value directly. Keep the
        // boundary compatible, then apply the same closed record validation
        // to either shape before exposing a saved link to the UI.
        const stored = result.data as unknown;
        const value = stored !== null && typeof stored === "object" && Object.hasOwn(stored, "value")
          ? (stored as { readonly value: unknown }).value
          : stored;
        const record = validateSenderHistoryRecord(value);
        if (seenDigests.has(record.urlDigest)) continue;
        seenDigests.add(record.urlDigest);
        items.push({ key, record, state: Date.parse(record.expiresAt) <= this.now() ? "expired" : "ready" });
      } catch {
        items.push({ key, state: "needs-attention", reason: "unsupported" });
      }
    }
    return { items, truncated: listedPage.truncated, ...(listedPage.nextCursor === undefined ? {} : { nextCursor: listedPage.nextCursor }) };
  }

  static keyFor(record: SenderHistoryRecord): string { return keyFor(record); }
}
