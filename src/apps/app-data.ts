/**
 * The runner's data port (`AppData`, bridge.ts) over a TinyCloud client's key-value
 * and SQL services. Pure plumbing: it adds no check, no scope and no authority of
 * its own. Which paths and statements reach it is decided by the bridge before it
 * is called, and what the call may do is decided by the node from the session's
 * signed ReCap.
 *
 * It is built from the services of a client that holds NO signer (run-session.ts):
 * the services invoke with the session key and nothing else, so a call the ReCap
 * does not cover is refused by the node rather than escalated.
 */
import { type AppData, type PortResult, type SqlParam, isBytes } from "./bridge.ts";

type SdkResult<T> = { readonly ok: true; readonly data: T } | { readonly ok: false; readonly error: { readonly code?: string; readonly message?: string } };

/** The parts of the SDK's key-value service the port uses. The real service satisfies this structurally. */
export interface SdkKv {
  get(key: string, options: { binary: true }): Promise<SdkResult<{ readonly data: unknown; readonly headers?: { readonly contentType?: string } | undefined }>>;
  put(key: string, value: string | Uint8Array, options: { contentType: string; ifNoneMatch?: "*" }): Promise<SdkResult<unknown>>;
  list(options: { prefix: string }): Promise<SdkResult<{ readonly keys: readonly string[]; readonly truncated?: boolean }>>;
  delete(key: string): Promise<SdkResult<unknown>>;
}

/** What the SDK binds: SQLite has no boolean, so true and false become 1 and 0. */
type SdkValue = string | number | null;

/** The parts of the SDK's SQL service the port uses. */
export interface SdkSql {
  db(name: string): {
    query(text: string, params: SdkValue[]): Promise<SdkResult<{ readonly columns: readonly string[]; readonly rows: readonly unknown[][]; readonly rowCount: number }>>;
    execute(text: string, params: SdkValue[]): Promise<SdkResult<{ readonly changes: number; readonly lastInsertRowId: number | null }>>;
  };
}

/** Bytes from whatever the SDK returns for a binary read. */
function toBytes(data: unknown): Uint8Array | undefined {
  if (isBytes(data)) return data;
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  if (typeof data === "string") return new TextEncoder().encode(data);
  // Some transports hand back an object with numeric keys.
  if (typeof data === "object" && data !== null) {
    const values = Object.values(data);
    if (values.every((value): value is number => typeof value === "number" && Number.isInteger(value) && value >= 0 && value <= 255)) return Uint8Array.from(values);
  }
  return undefined;
}

const bind = (params: readonly SqlParam[]): SdkValue[] => params.map((param) => (typeof param === "boolean" ? (param ? 1 : 0) : param));

export function createAppData(kv: SdkKv, sql: SdkSql): AppData {
  return {
    async kvGet(path): Promise<PortResult<{ readonly bytes: Uint8Array; readonly contentType?: string | undefined }>> {
      const result = await kv.get(path, { binary: true });
      if (!result.ok) return result;
      const bytes = toBytes(result.data.data);
      if (bytes === undefined) return { ok: false, error: { code: "INTERNAL", message: "The stored value could not be read as bytes." } };
      return { ok: true, data: { bytes, contentType: result.data.headers?.contentType } };
    },
    async kvPut(path, body, options): Promise<PortResult<unknown>> {
      return kv.put(path, body, { contentType: options.contentType, ...(options.ifNoneMatch ? { ifNoneMatch: "*" as const } : {}) });
    },
    async kvList(prefix): Promise<PortResult<{ readonly keys: readonly string[]; readonly truncated: boolean }>> {
      const result = await kv.list({ prefix });
      return result.ok ? { ok: true, data: { keys: result.data.keys, truncated: result.data.truncated === true } } : result;
    },
    async kvDelete(path): Promise<PortResult<unknown>> {
      return kv.delete(path);
    },
    async sqlQuery(db, text, params) {
      const result = await sql.db(db).query(text, bind(params));
      return result.ok ? { ok: true, data: { columns: result.data.columns, rows: result.data.rows, rowCount: result.data.rowCount } } : result;
    },
    async sqlExecute(db, text, params) {
      const result = await sql.db(db).execute(text, bind(params));
      return result.ok ? { ok: true, data: { changes: result.data.changes, lastInsertRowId: result.data.lastInsertRowId } } : result;
    },
  };
}
