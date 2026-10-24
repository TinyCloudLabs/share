import { newLinkId } from "../../src/bytes.ts";
import type { LinkType } from "../../src/config.ts";
import type { LinkRecord, SqlDriver } from "../../src/storage.ts";

export const NOW = 1_800_000_000;

export function makeRecord(overrides: Partial<LinkRecord> = {}): LinkRecord {
  const body = overrides.body ?? Uint8Array.from({ length: 64 }, (_, i) => i);
  return {
    id: newLinkId(),
    type: "share",
    issuer: "did:key:z6MktULudTtAsAhRegYPiZ6631RV3viv12qd4GQF8z1xB22S",
    issuedAt: NOW,
    expiresAt: NOW + 3600,
    size: body.length,
    bodyCid: "bafkreia2a2r36os6e5f44r336qxrufkiadw776sv2gxz5mt45yaefqmrl4",
    headerJcs: '{"audience":"https://api.tinycloud.xyz","version":1}',
    signature: "sig",
    body,
    addressHash: "addr-default",
    ...overrides,
  };
}

export interface SeedOptions {
  readonly idPrefix: string;
  readonly type: LinkType;
  readonly count: number;
  /** Size recorded on each seeded row (the body is empty). */
  readonly size: number;
  readonly address: string;
  readonly expiresAt?: number;
}

/** Inserts `count` synthetic live rows in one statement, to put a table in a given state. */
export async function seedRows(driver: SqlDriver, options: SeedOptions): Promise<void> {
  if (options.count <= 0) {
    return;
  }
  await driver.run(
    `WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < ?)
     INSERT INTO links (id, type, issuer, issued_at, expires_at, size, body_cid, header_jcs, signature, body, address_hash, created_at)
     SELECT ? || printf('%08d', i), ?, 'did:key:seed', 0, ?, ?, 'cid', '{}', NULL, x'', ?, 0 FROM n`,
    [options.count, options.idPrefix, options.type, options.expiresAt ?? NOW + 86_400, options.size, options.address],
  );
}
