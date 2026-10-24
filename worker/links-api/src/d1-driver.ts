import type { SqlDriver, SqlStatement, SqlValue } from "./storage.ts";
import type { D1Meta, UsageTally } from "./usage.ts";

/** The subset of the D1 binding the service uses. */
export interface D1Result<T = Record<string, unknown>> {
  readonly results?: T[];
  readonly meta: D1Meta & { readonly changes: number };
}

export interface D1PreparedStatement {
  bind(...values: unknown[]): D1PreparedStatement;
  run(): Promise<D1Result>;
  all<T = Record<string, unknown>>(): Promise<D1Result<T> & { readonly results: T[] }>;
}

export interface D1Database {
  prepare(query: string): D1PreparedStatement;
  batch(statements: D1PreparedStatement[]): Promise<D1Result[]>;
}

/** Cloudflare D1 behind the storage SQL surface; every result's `meta` goes to the usage tally. */
export class D1Driver implements SqlDriver {
  private readonly db: D1Database;
  private readonly tally: UsageTally | null;

  constructor(db: D1Database, tally: UsageTally | null = null) {
    this.db = db;
    this.tally = tally;
  }

  private prepare(sql: string, params: readonly SqlValue[]): D1PreparedStatement {
    return this.db.prepare(sql).bind(...params);
  }

  async run(sql: string, params: readonly SqlValue[]): Promise<number> {
    const result = await this.prepare(sql, params).run();
    this.tally?.record(result.meta);
    return result.meta.changes;
  }

  async first<T>(sql: string, params: readonly SqlValue[]): Promise<T | null> {
    return (await this.all<T>(sql, params))[0] ?? null;
  }

  async all<T>(sql: string, params: readonly SqlValue[]): Promise<T[]> {
    const result = await this.prepare(sql, params).all<T>();
    this.tally?.record(result.meta);
    return result.results;
  }

  async batch(statements: readonly SqlStatement[]): Promise<number[]> {
    const results = await this.db.batch(statements.map((s) => this.prepare(s.sql, s.params)));
    for (const result of results) {
      this.tally?.record(result.meta);
    }
    return results.map((r) => r.meta.changes);
  }
}
