/**
 * `import { sql, kv } from "@tinycloud/app"`: the in-frame client of the runner's
 * `cap/*` bridge. Runs ONLY inside the opaque-origin child frame of an installed
 * app (the module file is sent to runner frames only; see JSX_MODULE_SPECS).
 *
 * It is a thin client. It holds no secret and decides nothing: every call
 * becomes one `{v:1, type:"cap/<op>", id, args}` message to the frame's parent
 * (the bridge document), and the promise resolves with the `cap/result` the
 * runner page answered. What the call may touch is checked by the runner page
 * against the app's manifest, and again by the TinyCloud node.
 *
 * Contract (the same as the kit's dev shim, examples/sample-healthlog/dev/shim.mjs):
 * nothing here throws or rejects; every call resolves `{ ok: true, ... }` or
 * `{ ok: false, error: { code, message } }`.
 *
 *   kv.get(key)                      -> { ok, bytes: Uint8Array, contentType? }
 *   kv.put(key, body, opts?)         -> { ok }       body: string | Uint8Array; opts: { contentType?, ifNoneMatch?: true }
 *   kv.list(prefix = "")             -> { ok, keys: string[], truncated }
 *   kv.del(key)                      -> { ok }
 *   sql.query(db, text, params = []) -> { ok, columns, rows, rowCount }     one read-only statement
 *   sql.execute(db, text, params=[]) -> { ok, changes, lastInsertRowId }   one write or schema statement
 */
import { CAP_LIMITS, CAP_RESULT_TYPE, capError, type CapOp, type CapResult } from "./cap-protocol.js";

interface Waiting {
  readonly resolve: (result: CapResult) => void;
  readonly timer: number;
}

const waiting = new Map<string, Waiting>();
let counter = 0;
let listening = false;

function finish(id: string, result: CapResult): void {
  const entry = waiting.get(id);
  if (entry === undefined) return;
  waiting.delete(id);
  window.clearTimeout(entry.timer);
  entry.resolve(result);
}

function isPlainResult(value: unknown): value is CapResult {
  return typeof value === "object" && value !== null && !Array.isArray(value) && "ok" in value && typeof value.ok === "boolean";
}

function listen(): void {
  if (listening) return;
  listening = true;
  window.addEventListener("message", (event: MessageEvent) => {
    // Only the bridge document (this frame's parent) answers.
    if (event.source !== window.parent) return;
    const data: unknown = event.data;
    if (typeof data !== "object" || data === null || !("v" in data) || data.v !== 1 || !("type" in data) || data.type !== CAP_RESULT_TYPE || !("id" in data) || typeof data.id !== "string") return;
    const result = "result" in data ? data.result : undefined;
    finish(data.id, isPlainResult(result) ? result : capError("INTERNAL", "The runner sent an answer this app could not read."));
  });
}

function send(op: CapOp, args: Record<string, unknown>): Promise<CapResult> {
  return new Promise<CapResult>((resolve) => {
    try {
      listen();
      counter = counter >= 999_999_999 ? 1 : counter + 1;
      const id = String(counter);
      const timer = window.setTimeout(() => finish(id, capError("TIMEOUT", "No answer from the runner. The call may still have been applied: read it back before retrying a write.")), CAP_LIMITS.clientWaitMs);
      waiting.set(id, { resolve, timer });
      window.parent.postMessage({ v: 1, type: `cap/${op}`, id, args }, "*");
    } catch (error) {
      // A value the browser cannot clone (a function, a symbol) lands here.
      resolve(capError("BAD_REQUEST", `The call could not be sent: ${error instanceof Error ? error.message : "unsupported value"}`));
    }
  });
}

const bad = (message: string): Promise<CapResult> => Promise.resolve(capError("BAD_REQUEST", message));
const isText = (value: unknown): value is string => typeof value === "string";

/** `{ contentType?: string, ifNoneMatch?: true }` as plain data, or null for anything else. */
function putOptions(raw: unknown): { contentType?: string; ifNoneMatch?: true } | null {
  if (raw === undefined || raw === null) return {};
  if (typeof raw !== "object" || Array.isArray(raw)) return null;
  try {
    if (Object.keys(raw).some((key) => key !== "contentType" && key !== "ifNoneMatch")) return null;
    const out: { contentType?: string; ifNoneMatch?: true } = {};
    const contentType: unknown = "contentType" in raw ? raw.contentType : undefined;
    const ifNoneMatch: unknown = "ifNoneMatch" in raw ? raw.ifNoneMatch : undefined;
    if (contentType !== undefined) {
      if (!isText(contentType) || contentType.length > 200) return null;
      out.contentType = contentType;
    }
    if (ifNoneMatch !== undefined) {
      if (ifNoneMatch !== true) return null;
      out.ifNoneMatch = true;
    }
    return out;
  } catch {
    return null;
  }
}

function sqlArgs(op: "sql.query" | "sql.execute", db: unknown, text: unknown, params: unknown): Promise<CapResult> {
  if (!isText(db)) return bad("The database name must be a string.");
  if (!isText(text)) return bad("The SQL must be a string.");
  if (!Array.isArray(params)) return bad("params must be an array.");
  return send(op, { db, sql: text, params: [...params] });
}

export const kv = Object.freeze({
  get: (key: unknown): Promise<CapResult> => (isText(key) ? send("kv.get", { key }) : bad("The key must be a string.")),
  put: (key: unknown, body: unknown, options?: unknown): Promise<CapResult> => {
    if (!isText(key)) return bad("The key must be a string.");
    if (!isText(body) && !(body instanceof Uint8Array)) return bad("body must be a string or Uint8Array.");
    const clean = putOptions(options);
    if (clean === null) return bad("opts must be { contentType?: string, ifNoneMatch?: true }.");
    return send("kv.put", { key, body, ...clean });
  },
  list: (prefix: unknown = ""): Promise<CapResult> => (isText(prefix) ? send("kv.list", { key: prefix }) : bad("The prefix must be a string.")),
  del: (key: unknown): Promise<CapResult> => (isText(key) ? send("kv.del", { key }) : bad("The key must be a string.")),
});

export const sql = Object.freeze({
  query: (db: unknown, text: unknown, params: unknown = []): Promise<CapResult> => sqlArgs("sql.query", db, text, params),
  execute: (db: unknown, text: unknown, params: unknown = []): Promise<CapResult> => sqlArgs("sql.execute", db, text, params),
});
