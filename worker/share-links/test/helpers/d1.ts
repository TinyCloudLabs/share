import { readFileSync } from "node:fs";
import { DatabaseSync, type SQLInputValue } from "node:sqlite";
import { fileURLToPath } from "node:url";
import type { D1Database, D1PreparedStatement, D1RunResult } from "../../src/d1";

const MIGRATION = fileURLToPath(new URL("../../migrations/0001_init.sql", import.meta.url));

class Statement implements D1PreparedStatement {
  private values: SQLInputValue[] = [];

  constructor(
    private readonly raw: DatabaseSync,
    private readonly sql: string,
  ) {}

  bind(...values: unknown[]): D1PreparedStatement {
    this.values = values as SQLInputValue[];
    return this;
  }

  async run(): Promise<D1RunResult> {
    const info = this.raw.prepare(this.sql).run(...this.values);
    return { success: true, meta: { changes: Number(info.changes) } };
  }

  async first<T = Record<string, unknown>>(): Promise<T | null> {
    const row = this.raw.prepare(this.sql).get(...this.values);
    return (row ?? null) as T | null;
  }
}

export interface TestDb {
  db: D1Database;
  raw: DatabaseSync;
}

/** Fresh in-memory database with the production migration applied. */
export function makeTestDb(): TestDb {
  const raw = new DatabaseSync(":memory:");
  raw.exec(readFileSync(MIGRATION, "utf8"));
  const db: D1Database = {
    prepare: (sql) => new Statement(raw, sql),
    batch: async (statements) => {
      const results: D1RunResult[] = [];
      for (const statement of statements) {
        results.push(await statement.run());
      }
      return results;
    },
  };
  return { db, raw };
}
