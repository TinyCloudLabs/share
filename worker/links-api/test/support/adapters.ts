import { readFileSync } from "node:fs";
import { Miniflare } from "miniflare";
import { D1Driver, type D1Database } from "../../src/d1-driver.ts";
import { DEFAULT_ADMISSION, SqlStorage, type Admission } from "../../src/sql-storage.ts";
import { SqliteDriver } from "../../src/sqlite-driver.ts";
import type { LinkStorage, SqlDriver } from "../../src/storage.ts";

const MIGRATION = new URL("../../migrations/0001_init.sql", import.meta.url);
const TABLES = ["links", "rl", "nonces", "blocked", "api_keys", "metrics", "usage_daily"];

/** One adapter under test: a storage plus the raw SQL surface used to seed state. */
export interface Adapter {
  readonly name: "d1" | "sqlite";
  readonly driver: SqlDriver;
  storage(rules?: Admission): LinkStorage;
  /** Empties every table. */
  reset(): Promise<void>;
  close(): Promise<void>;
}

function migrationStatements(): string[] {
  return readFileSync(MIGRATION, "utf8")
    .split("\n")
    .filter((line) => !line.startsWith("--"))
    .join("\n")
    .split(";")
    .map((s) => s.replace(/\s+/g, " ").trim())
    .filter((s) => s.length > 0);
}

export async function createSqliteAdapter(): Promise<Adapter> {
  const driver = new SqliteDriver(":memory:");
  return {
    name: "sqlite",
    driver,
    storage: (rules = DEFAULT_ADMISSION) => new SqlStorage(driver, rules),
    reset: async () => {
      for (const table of TABLES) {
        driver.exec(`DELETE FROM ${table}`);
      }
    },
    close: async () => driver.close(),
  };
}

/** A local D1 database from miniflare (workerd's SQLite); nothing leaves the machine. */
export async function createD1Adapter(): Promise<Adapter> {
  const mf = new Miniflare({
    modules: true,
    script: "export default { fetch() { return new Response('unused'); } }",
    compatibilityDate: "2025-09-01",
    d1Databases: ["DB"],
  });
  const db = (await mf.getD1Database("DB")) as unknown as D1Database;
  await db.batch(migrationStatements().map((sql) => db.prepare(sql)));
  const driver = new D1Driver(db);
  return {
    name: "d1",
    driver,
    storage: (rules = DEFAULT_ADMISSION) => new SqlStorage(driver, rules),
    reset: async () => {
      await db.batch(TABLES.map((table) => db.prepare(`DELETE FROM ${table}`)));
    },
    close: async () => {
      await mf.dispose();
    },
  };
}

export const ADAPTER_FACTORIES = [
  { name: "sqlite", create: createSqliteAdapter },
  { name: "d1", create: createD1Adapter },
] as const;
