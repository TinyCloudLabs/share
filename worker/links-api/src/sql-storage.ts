import { ADDRESS_LIVE_CAP, LINK_TYPES, READ_ONCE_TYPES, RESERVE, TYPE_CONFIG, type LinkType } from "./config.ts";
import type {
  ApiKeyRecord,
  BlockKind,
  HitResult,
  LinkRecord,
  LinkStorage,
  PutOutcome,
  SqlDriver,
  StatsByType,
  TypeStats,
} from "./storage.ts";
import { utcDay } from "./usage.ts";

/** Live rows and bytes of the record's type and of its address bucket, as the insert sees them. */
export interface AdmissionState {
  readonly typeRows: number;
  readonly typeBytes: number;
  readonly addressRows: number;
  readonly addressBytes: number;
}

export interface Admission {
  readonly addressRows: number;
  readonly addressBytes: number;
  readonly reserveFraction: number;
  readonly reserveAddressRows: number;
  readonly types: Readonly<Record<LinkType, { readonly quotaRows: number; readonly quotaBytes: number }>>;
}

export const DEFAULT_ADMISSION: Admission = {
  addressRows: ADDRESS_LIVE_CAP.rows,
  addressBytes: ADDRESS_LIVE_CAP.bytes,
  reserveFraction: RESERVE.highWaterFraction,
  reserveAddressRows: RESERVE.addressRowsAtOrAboveHighWater,
  types: TYPE_CONFIG,
};

/** The admission rule the insert statement applies, in its order: address cap, reserve, type quota. */
export function admit(
  state: AdmissionState,
  type: LinkType,
  bytes: number,
  rules: Admission = DEFAULT_ADMISSION,
): "ok" | "address_live_cap" | "reserve" | "type_quota" {
  const quota = rules.types[type];
  if (state.addressRows + 1 > rules.addressRows || state.addressBytes + bytes > rules.addressBytes) {
    return "address_live_cap";
  }
  if (state.typeRows >= quota.quotaRows * rules.reserveFraction && state.addressRows >= rules.reserveAddressRows) {
    return "reserve";
  }
  if (state.typeRows + 1 > quota.quotaRows || state.typeBytes + bytes > quota.quotaBytes) {
    return "type_quota";
  }
  return "ok";
}

const COLUMNS = "id, type, issuer, issued_at, expires_at, size, body_cid, header_jcs, signature, body, address_hash";
const READ_ONCE_SQL = READ_ONCE_TYPES.map((t) => `'${t}'`).join(", ");

interface LinkRow {
  id: string;
  type: LinkType;
  issuer: string;
  issued_at: number;
  expires_at: number;
  size: number;
  body_cid: string;
  header_jcs: string;
  signature: string | null;
  body: unknown;
  address_hash: string;
}

/** Blob columns come back as ArrayBuffer, a typed array or number[], depending on the driver. */
function toBytes(value: unknown): Uint8Array {
  if (value instanceof Uint8Array) {
    return value;
  }
  if (value instanceof ArrayBuffer) {
    return new Uint8Array(value);
  }
  if (Array.isArray(value)) {
    return Uint8Array.from(value as number[]);
  }
  throw new TypeError("unexpected blob type");
}

function toRecord(row: LinkRow): LinkRecord {
  return {
    id: row.id,
    type: row.type,
    issuer: row.issuer,
    issuedAt: row.issued_at,
    expiresAt: row.expires_at,
    size: row.size,
    bodyCid: row.body_cid,
    headerJcs: row.header_jcs,
    signature: row.signature,
    body: toBytes(row.body),
    addressHash: row.address_hash,
  };
}

const MAX_PUT_ATTEMPTS = 3;

/** The storage interface over any SQLite-dialect driver: D1 and the self-host file run this one statement set. */
export class SqlStorage implements LinkStorage {
  private readonly db: SqlDriver;
  private readonly rules: Admission;

  constructor(db: SqlDriver, rules: Admission = DEFAULT_ADMISSION) {
    this.db = db;
    this.rules = rules;
  }

  async put(record: LinkRecord, now: number): Promise<PutOutcome> {
    const quota = this.rules.types[record.type];
    for (let attempt = 0; attempt < MAX_PUT_ATTEMPTS; attempt++) {
      // One statement: the admission checks and the insert cannot be split by a concurrent put.
      // The type and address totals are each computed once.
      const changed = await this.db.run(
        `WITH ty AS MATERIALIZED (SELECT count(*) AS c, coalesce(sum(size), 0) AS b FROM links WHERE type = ? AND expires_at > ?),
              ad AS MATERIALIZED (SELECT count(*) AS c, coalesce(sum(size), 0) AS b FROM links WHERE address_hash = ? AND expires_at > ?)
         INSERT INTO links (${COLUMNS}, created_at)
         SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ? FROM ty, ad
         WHERE ad.c < ? AND ad.b + ? <= ?
           AND NOT (ty.c >= ? AND ad.c >= ?)
           AND ty.c < ? AND ty.b + ? <= ?
         ON CONFLICT(id) DO NOTHING`,
        [
          record.type,
          now,
          record.addressHash,
          now,
          record.id,
          record.type,
          record.issuer,
          record.issuedAt,
          record.expiresAt,
          record.size,
          record.bodyCid,
          record.headerJcs,
          record.signature,
          record.body,
          record.addressHash,
          now,
          this.rules.addressRows,
          record.size,
          this.rules.addressBytes,
          quota.quotaRows * this.rules.reserveFraction,
          this.rules.reserveAddressRows,
          quota.quotaRows,
          record.size,
          quota.quotaBytes,
        ],
      );
      if (changed === 1) {
        return "ok";
      }
      const existing = await this.db.first<{ found: number }>("SELECT 1 AS found FROM links WHERE id = ?", [record.id]);
      if (existing) {
        return "exists";
      }
      const state = await this.admissionState(record, now);
      const verdict = admit(state, record.type, record.size, this.rules);
      if (verdict !== "ok") {
        return verdict;
      }
    }
    throw new Error("put: admission did not settle");
  }

  private async admissionState(record: LinkRecord, now: number): Promise<AdmissionState> {
    const row = await this.db.first<{ type_rows: number; type_bytes: number; address_rows: number; address_bytes: number }>(
      `SELECT
         (SELECT count(*) FROM links WHERE type = ? AND expires_at > ?) AS type_rows,
         (SELECT coalesce(sum(size), 0) FROM links WHERE type = ? AND expires_at > ?) AS type_bytes,
         (SELECT count(*) FROM links WHERE address_hash = ? AND expires_at > ?) AS address_rows,
         (SELECT coalesce(sum(size), 0) FROM links WHERE address_hash = ? AND expires_at > ?) AS address_bytes`,
      [record.type, now, record.type, now, record.addressHash, now, record.addressHash, now],
    );
    return {
      typeRows: row?.type_rows ?? 0,
      typeBytes: row?.type_bytes ?? 0,
      addressRows: row?.address_rows ?? 0,
      addressBytes: row?.address_bytes ?? 0,
    };
  }

  async get(id: string, now: number): Promise<LinkRecord | null> {
    const row = await this.db.first<LinkRow>(
      `SELECT ${COLUMNS} FROM links WHERE id = ? AND expires_at > ? AND type NOT IN (${READ_ONCE_SQL})`,
      [id, now],
    );
    return row ? toRecord(row) : null;
  }

  async take(id: string, now: number): Promise<LinkRecord | null> {
    const row = await this.db.first<LinkRow>(
      `DELETE FROM links WHERE id = ? AND expires_at > ? AND type IN (${READ_ONCE_SQL}) RETURNING ${COLUMNS}`,
      [id, now],
    );
    return row ? toRecord(row) : null;
  }

  async delete(id: string, issuer: string, now: number): Promise<boolean> {
    return (await this.db.run("DELETE FROM links WHERE id = ? AND issuer = ? AND expires_at > ?", [id, issuer, now])) === 1;
  }

  async sweep(now: number): Promise<number> {
    const changes = await this.db.batch([
      { sql: "DELETE FROM links WHERE expires_at <= ?", params: [now] },
      { sql: "DELETE FROM nonces WHERE exp <= ?", params: [now] },
      { sql: "DELETE FROM rl WHERE exp <= ?", params: [now] },
      { sql: "DELETE FROM usage_daily WHERE day < ?", params: [utcDay(now - 86_400)] },
    ]);
    return changes.reduce((sum, n) => sum + n, 0);
  }

  async addUsage(day: string, deltas: Readonly<Record<string, number>>): Promise<Readonly<Record<string, number>>> {
    const adds = Object.entries(deltas).filter(([, n]) => n > 0);
    if (adds.length > 0) {
      await this.db.batch(
        adds.map(([metric, n]) => ({
          sql: "INSERT INTO usage_daily (day, metric, n) VALUES (?, ?, ?) ON CONFLICT(day, metric) DO UPDATE SET n = n + excluded.n",
          params: [day, metric, n],
        })),
      );
    }
    const rows = await this.db.all<{ metric: string; n: number }>("SELECT metric, n FROM usage_daily WHERE day = ?", [day]);
    return Object.fromEntries(rows.map((r) => [r.metric, r.n]));
  }

  async claimAlert(day: string, metric: string): Promise<boolean> {
    const changed = await this.db.run(
      `INSERT INTO usage_daily (day, metric, n, alerted) VALUES (?, ?, 0, 1)
       ON CONFLICT(day, metric) DO UPDATE SET alerted = 1 WHERE alerted = 0`,
      [day, metric],
    );
    return changed === 1;
  }

  async hit(key: string, limit: number, windowSeconds: number, now: number): Promise<HitResult> {
    const bucket = Math.floor(now / windowSeconds);
    const windowEnd = (bucket + 1) * windowSeconds;
    const row = await this.db.first<{ n: number }>(
      "INSERT INTO rl (k, n, exp) VALUES (?, 1, ?) ON CONFLICT(k) DO UPDATE SET n = n + 1 RETURNING n",
      [`${key}:${bucket}`, windowEnd],
    );
    return { allowed: (row?.n ?? 0) <= limit, retryAfter: Math.max(1, windowEnd - now) };
  }

  async peek(key: string, limit: number, windowSeconds: number, now: number): Promise<HitResult> {
    const bucket = Math.floor(now / windowSeconds);
    const windowEnd = (bucket + 1) * windowSeconds;
    const row = await this.db.first<{ n: number }>("SELECT n FROM rl WHERE k = ?", [`${key}:${bucket}`]);
    return { allowed: (row?.n ?? 0) < limit, retryAfter: Math.max(1, windowEnd - now) };
  }

  async claimNonce(scope: string, nonceHash: string, ttlSeconds: number, now: number): Promise<boolean> {
    // The conflict update applies only when the stored claim has ended, so one claim wins per TTL.
    const changed = await this.db.run(
      `INSERT INTO nonces (scope, nonce_hash, exp) VALUES (?, ?, ?)
       ON CONFLICT(scope, nonce_hash) DO UPDATE SET exp = excluded.exp WHERE nonces.exp <= ?`,
      [scope, nonceHash, now + ttlSeconds, now],
    );
    return changed === 1;
  }

  async isBlocked(kind: BlockKind, key: string): Promise<boolean> {
    return (await this.db.first("SELECT 1 AS found FROM blocked WHERE kind = ? AND key = ?", [kind, key])) !== null;
  }

  async setBlocked(kind: BlockKind, key: string, note: string, now: number): Promise<void> {
    await this.db.run("INSERT OR REPLACE INTO blocked (kind, key, since, note) VALUES (?, ?, ?, ?)", [kind, key, now, note]);
  }

  async clearBlocked(kind: BlockKind, key: string): Promise<void> {
    await this.db.run("DELETE FROM blocked WHERE kind = ? AND key = ?", [kind, key]);
  }

  async apiKey(keyId: string): Promise<ApiKeyRecord | null> {
    const row = await this.db.first<{ key_id: string; service: string; allowed_types: string; secret_sha256: string }>(
      "SELECT key_id, service, allowed_types, secret_sha256 FROM api_keys WHERE key_id = ? AND revoked_at IS NULL",
      [keyId],
    );
    if (!row) {
      return null;
    }
    const types = (JSON.parse(row.allowed_types) as string[]).filter((t): t is LinkType =>
      (LINK_TYPES as readonly string[]).includes(t),
    );
    return { keyId: row.key_id, service: row.service, allowedTypes: types, secretSha256: row.secret_sha256 };
  }

  async addApiKey(key: ApiKeyRecord, now: number): Promise<boolean> {
    const changed = await this.db.run(
      `INSERT INTO api_keys (key_id, service, allowed_types, secret_sha256, created_at, revoked_at)
       SELECT ?, ?, ?, ?, ?, NULL
       WHERE (SELECT count(*) FROM api_keys WHERE service = ? AND revoked_at IS NULL) < 2`,
      [key.keyId, key.service, JSON.stringify(key.allowedTypes), key.secretSha256, now, key.service],
    );
    return changed === 1;
  }

  async revokeApiKey(keyId: string, now: number): Promise<void> {
    await this.db.run("UPDATE api_keys SET revoked_at = ? WHERE key_id = ? AND revoked_at IS NULL", [now, keyId]);
  }

  async stats(now: number): Promise<StatsByType> {
    const rows = await this.db.all<{ type: LinkType; rows: number; bytes: number }>(
      "SELECT type, count(*) AS rows, coalesce(sum(size), 0) AS bytes FROM links WHERE expires_at > ? GROUP BY type",
      [now],
    );
    const out: Record<string, TypeStats> = {};
    for (const type of LINK_TYPES) {
      const found = rows.find((r) => r.type === type);
      out[type] = { rows: found?.rows ?? 0, bytes: found?.bytes ?? 0 };
    }
    return out as StatsByType;
  }

  async count(metric: string, n: number): Promise<void> {
    await this.db.run("INSERT INTO metrics (name, n) VALUES (?, ?) ON CONFLICT(name) DO UPDATE SET n = n + excluded.n", [metric, n]);
  }

  async readCounts(): Promise<Readonly<Record<string, number>>> {
    const rows = await this.db.all<{ name: string; n: number }>("DELETE FROM metrics RETURNING name, n", []);
    return Object.fromEntries(rows.map((r) => [r.name, r.n]));
  }
}
