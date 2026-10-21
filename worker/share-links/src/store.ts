import type { D1Database } from "./d1";

export const MAX_LIVE_ROWS = 20_000;
export const MAX_LIVE_BYTES = 2 * 1024 * 1024 * 1024;

export type InsertOutcome = "ok" | "collision" | "capacity";

export interface NewLink {
  id: string;
  ciphertext: Uint8Array;
  cid: string;
  expiresAtSeconds: number;
  deleteHash: string;
  nowSeconds: number;
}

/**
 * Single-statement insert. The live-count and live-bytes checks run inside the
 * same statement as the insert, so the cap cannot be overshot by concurrent
 * creates. `ON CONFLICT(id) DO NOTHING` reports id collisions as zero changes.
 */
export async function insertLink(db: D1Database, link: NewLink): Promise<InsertOutcome> {
  const size = link.ciphertext.length;
  const result = await db
    .prepare(
      `INSERT INTO links (id, ciphertext, cid, expires_at, delete_hash, size, created_at, deleted_at)
       SELECT ?, ?, ?, ?, ?, ?, ?, NULL
       WHERE (SELECT count(*) FROM links WHERE deleted_at IS NULL AND expires_at > ?) < ?
         AND (SELECT coalesce(sum(size), 0) FROM links WHERE deleted_at IS NULL AND expires_at > ?) + ? <= ?
       ON CONFLICT(id) DO NOTHING`,
    )
    .bind(
      link.id,
      link.ciphertext,
      link.cid,
      link.expiresAtSeconds,
      link.deleteHash,
      size,
      link.nowSeconds,
      link.nowSeconds,
      MAX_LIVE_ROWS,
      link.nowSeconds,
      size,
      MAX_LIVE_BYTES,
    )
    .run();
  if (result.meta.changes === 1) {
    return "ok";
  }
  const existing = await db
    .prepare("SELECT 1 AS found FROM links WHERE id = ?")
    .bind(link.id)
    .first<{ found: number }>();
  return existing ? "collision" : "capacity";
}

export interface LiveRead {
  ciphertext: unknown;
  cid: string;
  expires_at: number;
}

export async function readLiveLink(
  db: D1Database,
  id: string,
  nowSeconds: number,
): Promise<LiveRead | null> {
  return db
    .prepare(
      "SELECT ciphertext, cid, expires_at FROM links WHERE id = ? AND deleted_at IS NULL AND expires_at > ?",
    )
    .bind(id, nowSeconds)
    .first<LiveRead>();
}

export async function readLiveDeleteHash(
  db: D1Database,
  id: string,
  nowSeconds: number,
): Promise<string | null> {
  const row = await db
    .prepare(
      "SELECT delete_hash FROM links WHERE id = ? AND deleted_at IS NULL AND expires_at > ?",
    )
    .bind(id, nowSeconds)
    .first<{ delete_hash: string }>();
  return row?.delete_hash ?? null;
}

/** Tombstone: drop ciphertext, zero size, keep the row until its original expiry. */
export async function tombstoneLink(
  db: D1Database,
  id: string,
  nowSeconds: number,
): Promise<boolean> {
  const result = await db
    .prepare(
      "UPDATE links SET ciphertext = x'', size = 0, deleted_at = ? WHERE id = ? AND deleted_at IS NULL AND expires_at > ?",
    )
    .bind(nowSeconds, id, nowSeconds)
    .run();
  return result.meta.changes === 1;
}

export async function runCleanup(db: D1Database, nowSeconds: number): Promise<void> {
  await db.batch([
    db.prepare("DELETE FROM links WHERE expires_at < ?").bind(nowSeconds),
    db.prepare("DELETE FROM rl WHERE exp < ?").bind(nowSeconds),
  ]);
}
