import type { LinkType } from "./config.ts";

/**
 * The one storage interface (contract 9.1). Every operation takes an explicit `now` in epoch
 * seconds, so tests are deterministic. Ids are lower case.
 */

export interface LinkRecord {
  readonly id: string;
  readonly type: LinkType;
  readonly issuer: string;
  /** Epoch seconds of the signed `issuedAt`. */
  readonly issuedAt: number;
  /** Epoch seconds of the signed `expiresAt`, rounded down; a record is dead when `expiresAt <= now`. */
  readonly expiresAt: number;
  readonly size: number;
  readonly bodyCid: string;
  /** The canonical (JCS) header text exactly as signed. */
  readonly headerJcs: string;
  /** base64url of the 64 signature bytes; null for API-key records. */
  readonly signature: string | null;
  readonly body: Uint8Array;
  /** Salted hash of the live-cap address bucket; lives and dies with the record. */
  readonly addressHash: string;
}

export type PutOutcome = "ok" | "exists" | "address_live_cap" | "reserve" | "type_quota";

export interface HitResult {
  readonly allowed: boolean;
  readonly retryAfter: number;
}

export type BlockKind = "issuer" | "address";

export interface ApiKeyRecord {
  readonly keyId: string;
  readonly service: string;
  readonly allowedTypes: readonly LinkType[];
  /** base64url(SHA-256(secret as UTF-8)). */
  readonly secretSha256: string;
}

export interface TypeStats {
  readonly rows: number;
  readonly bytes: number;
}

export type StatsByType = Readonly<Record<LinkType, TypeStats>>;

export interface LinkStorage {
  /** Insert if absent; address cap, then type reserve, then type quota, inside one statement. */
  put(record: LinkRecord, now: number): Promise<PutOutcome>;
  /** Live and not read-once; the same `null` for unknown, expired and read-once. */
  get(id: string, now: number): Promise<LinkRecord | null>;
  /** Live and read-once only; atomic get-and-delete. */
  take(id: string, now: number): Promise<LinkRecord | null>;
  /** One conditional statement: removes the live row whose id and issuer both match. */
  delete(id: string, issuer: string, now: number): Promise<boolean>;
  /** Removes expired records, expired nonces and expired counters; returns the number of rows removed. */
  sweep(now: number): Promise<number>;
  /** Atomic fixed-window counter, bucket `floor(now / windowSeconds)`. */
  hit(key: string, limit: number, windowSeconds: number, now: number): Promise<HitResult>;
  /** Current count of the window without counting a hit. */
  peek(key: string, limit: number, windowSeconds: number, now: number): Promise<HitResult>;
  /** Atomic; true only for the first claim inside the TTL. */
  claimNonce(scope: string, nonceHash: string, ttlSeconds: number, now: number): Promise<boolean>;
  isBlocked(kind: BlockKind, key: string): Promise<boolean>;
  setBlocked(kind: BlockKind, key: string, note: string, now: number): Promise<void>;
  clearBlocked(kind: BlockKind, key: string): Promise<void>;
  /** Not revoked only. */
  apiKey(keyId: string): Promise<ApiKeyRecord | null>;
  /** Operator side. Refuses (false) when the service already has two active keys. */
  addApiKey(key: ApiKeyRecord, now: number): Promise<boolean>;
  revokeApiKey(keyId: string, now: number): Promise<void>;
  /** Live rows and bytes per type; excludes expired records. */
  stats(now: number): Promise<StatsByType>;
  /** Atomic add to a health counter. */
  count(metric: string, n: number): Promise<void>;
  /** Adds to the day's usage totals (`day` is `YYYY-MM-DD`, UTC) and returns every total of that day. */
  addUsage(day: string, deltas: Readonly<Record<string, number>>): Promise<Readonly<Record<string, number>>>;
  /** True only for the first claim of the day's alert for a metric. */
  claimAlert(day: string, metric: string): Promise<boolean>;
  /** Atomic read-and-reset of every health counter. */
  readCounts(): Promise<Readonly<Record<string, number>>>;
}

/** The SQL surface both adapters provide; the storage statements are one set of SQL text. */
export interface SqlStatement {
  readonly sql: string;
  readonly params: readonly SqlValue[];
}

export type SqlValue = string | number | null | Uint8Array;

export interface SqlDriver {
  /** Number of rows changed. */
  run(sql: string, params: readonly SqlValue[]): Promise<number>;
  first<T>(sql: string, params: readonly SqlValue[]): Promise<T | null>;
  all<T>(sql: string, params: readonly SqlValue[]): Promise<T[]>;
  /** All statements in one transaction; rows changed per statement. */
  batch(statements: readonly SqlStatement[]): Promise<number[]>;
}
