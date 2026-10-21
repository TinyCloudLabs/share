export interface D1Meta {
  changes: number;
}

export interface D1RunResult {
  success?: boolean;
  meta: D1Meta;
}

export interface D1PreparedStatement {
  bind(...values: unknown[]): D1PreparedStatement;
  run(): Promise<D1RunResult>;
  first<T = Record<string, unknown>>(): Promise<T | null>;
}

export interface D1Database {
  prepare(query: string): D1PreparedStatement;
  batch(statements: D1PreparedStatement[]): Promise<D1RunResult[]>;
}

export interface Env {
  DB: D1Database;
}

/** D1 may hand BLOB columns back as ArrayBuffer, typed array, or number[]. */
export function toBytes(value: unknown): Uint8Array {
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
