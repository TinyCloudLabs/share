import { readFileSync } from "node:fs";
import { DatabaseSync, type SQLInputValue, type StatementSync } from "node:sqlite";
import type { SqlDriver, SqlStatement, SqlValue } from "./storage.ts";

const MIGRATION = new URL("../migrations/0001_init.sql", import.meta.url);

/** The self-host adapter: one SQLite file (or `:memory:`) behind the storage SQL surface. */
export class SqliteDriver implements SqlDriver {
  private readonly raw: DatabaseSync;
  private readonly cache = new Map<string, StatementSync>();

  constructor(path: string) {
    this.raw = new DatabaseSync(path);
    this.raw.exec("PRAGMA journal_mode = WAL");
    this.raw.exec("PRAGMA busy_timeout = 5000");
    const present = this.raw.prepare("SELECT 1 AS found FROM sqlite_master WHERE type = 'table' AND name = 'links'").get();
    if (!present) {
      this.raw.exec(readFileSync(MIGRATION, "utf8"));
    }
  }

  private statement(sql: string): StatementSync {
    let statement = this.cache.get(sql);
    if (statement === undefined) {
      statement = this.raw.prepare(sql);
      this.cache.set(sql, statement);
    }
    return statement;
  }

  private params(values: readonly SqlValue[]): SQLInputValue[] {
    return [...values];
  }

  async run(sql: string, params: readonly SqlValue[]): Promise<number> {
    return Number(this.statement(sql).run(...this.params(params)).changes);
  }

  async first<T>(sql: string, params: readonly SqlValue[]): Promise<T | null> {
    return (this.statement(sql).get(...this.params(params)) ?? null) as T | null;
  }

  async all<T>(sql: string, params: readonly SqlValue[]): Promise<T[]> {
    return this.statement(sql).all(...this.params(params)) as T[];
  }

  async batch(statements: readonly SqlStatement[]): Promise<number[]> {
    // No await inside the transaction: nothing else can interleave on this connection.
    this.raw.exec("BEGIN IMMEDIATE");
    try {
      const changes = statements.map((s) => Number(this.statement(s.sql).run(...this.params(s.params)).changes));
      this.raw.exec("COMMIT");
      return changes;
    } catch (err) {
      this.raw.exec("ROLLBACK");
      throw err;
    }
  }

  /** Test and shutdown access. */
  exec(sql: string): void {
    this.raw.exec(sql);
  }

  close(): void {
    this.raw.close();
  }
}
