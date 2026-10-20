/**
 * The runner page's side of the `cap/*` bridge: the ONE handler registered on the
 * JSX sandbox (`onCapability`, src/viewer/jsx-sandbox.ts). An installed app's
 * `import { sql, kv } from "@tinycloud/app"` becomes `cap/<op>` messages; this
 * module turns each into at most one call on the person's own TinyCloud and
 * answers with `{ ok: true, ... }` or `{ ok: false, error: { code, message } }`.
 *
 * Layers, in the order a call meets them:
 *   1. the frame's bridge document: known operation names only, plain data, 1 MB,
 *      4 in flight (src/viewer/jsx-frame.ts);
 *   2. this module, which trusts nothing the frame said: key set, id, types, size,
 *      statement class (sql-class.ts), path rules, then the app's RESOLVED manifest
 *      (`authorize`: (service, path, action)), BEFORE any SDK call;
 *   3. the TinyCloud node, which enforces the session's signed ReCap by ability and
 *      prefix. Step 2 is a UX and defence layer; the node is the boundary, and the
 *      session this page holds has no key that could sign for more (run-session.ts).
 *
 * Paths. `key` and `db` are relative to `<app_id>/`. A leading "/" names an absolute
 * path in the space and is allowed only where a `skipPrefix` grant of the manifest
 * covers it (the Recipes sample reads the Health Log database that way). The frame
 * cannot name a service, a space, a delegation or another session: the only things
 * it can say are the six operations below.
 *
 * `sql.execute` is limited to the app's OWN databases (a relative `db`), whatever the
 * manifest says: TC-1581 (the node lets a write ability run DDL) is not something
 * this page can fix, but it can refuse to be the way an app reaches another app's
 * database. Classification decides the ability needed: a CREATE/DROP/ALTER needs the
 * manifest's `schema`, an INSERT/UPDATE/DELETE needs `write`, a SELECT needs `read`.
 *
 * Nothing here throws into the frame: every path resolves to a result.
 */
import { CAP_ID_PATTERN, CAP_LIMITS, CAP_OPS, CAP_TYPE_PREFIX, CAP_MAX_ERROR_CHARS, capError, type CapError, type CapErrorCode, type CapOp, type CapResult } from "../artifact/jsx-runtime/cap-protocol.js";
import type { Authorizer, BridgeAction } from "./grants.ts";
import { classifySql } from "./sql-class.ts";

/** The SDK's result shape, as the data port returns it. */
export type PortResult<T> = { readonly ok: true; readonly data: T } | { readonly ok: false; readonly error: { readonly code?: string; readonly message?: string } };

/** The few calls the bridge makes on the person's TinyCloud. Paths are absolute in the app's space. */
export interface AppData {
  kvGet(path: string): Promise<PortResult<{ readonly bytes: Uint8Array; readonly contentType?: string | undefined }>>;
  kvPut(path: string, body: string | Uint8Array, options: { readonly contentType: string; readonly ifNoneMatch: boolean }): Promise<PortResult<unknown>>;
  kvList(prefix: string): Promise<PortResult<{ readonly keys: readonly string[]; readonly truncated: boolean }>>;
  kvDelete(path: string): Promise<PortResult<unknown>>;
  sqlQuery(db: string, text: string, params: readonly SqlParam[]): Promise<PortResult<{ readonly columns: readonly string[]; readonly rows: readonly unknown[][]; readonly rowCount: number }>>;
  sqlExecute(db: string, text: string, params: readonly SqlParam[]): Promise<PortResult<{ readonly changes: number; readonly lastInsertRowId: number | null }>>;
}

export type SqlParam = string | number | boolean | null;

export interface CapabilityRequest {
  readonly type: string;
  readonly body: unknown;
}

export interface BridgeOptions {
  readonly appId: string;
  readonly authorize: Authorizer;
  readonly data: AppData;
  /** Sends `cap/result` for a request id to the frame. */
  readonly reply: (id: string, result: CapResult) => void;
  /** False once the runtime session has ended: every call then answers NOT_CONNECTED. */
  readonly isLive?: () => boolean;
  readonly limits?: Partial<typeof CAP_LIMITS>;
}

export interface CapabilityBridge {
  /** Handles one request; never throws. */
  handle(request: CapabilityRequest): void;
  /** Calls running now (a call that timed out still counts until it settles, or its hold ends). */
  inFlight(): number;
  /** The page is going away: later requests are dropped and pending answers are not sent. */
  close(): void;
}

const isPlainObject = (value: unknown): value is Record<string, unknown> => {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const proto: unknown = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
};

/** A Uint8Array from any realm (the page's, the SDK's, or one structured-cloned in from a frame). */
export const isBytes = (value: unknown): value is Uint8Array => Object.prototype.toString.call(value) === "[object Uint8Array]";

/** UTF-8 length of a string without allocating it. */
function utf8Length(text: string): number {
  let bytes = 0;
  for (let i = 0; i < text.length; i += 1) {
    const unit = text.charCodeAt(i);
    if (unit < 0x80) bytes += 1;
    else if (unit < 0x800) bytes += 2;
    else if (unit >= 0xd800 && unit <= 0xdbff && i + 1 < text.length && (text.charCodeAt(i + 1) & 0xfc00) === 0xdc00) { bytes += 4; i += 1; }
    else bytes += 3;
  }
  return bytes;
}

/**
 * Size of call arguments or a result in bytes (strings as UTF-8, binary as is, 8 bytes
 * per other value, key names counted), or null when the value is not plain data: only
 * strings, finite numbers, booleans, null, arrays, plain objects and Uint8Array, nested
 * at most `maxDepth` deep. Stops as soon as `limit` is exceeded (the number returned
 * is then above it).
 */
export function dataSize(value: unknown, limit: number, maxDepth: number = CAP_LIMITS.maxDepth): number | null {
  let total = 0;
  const walk = (item: unknown, depth: number): boolean => {
    if (depth > maxDepth) return false;
    if (total > limit) return true;
    if (item === null || item === undefined || typeof item === "boolean") total += 8;
    else if (typeof item === "number") { if (!Number.isFinite(item)) return false; total += 8; }
    else if (typeof item === "string") total += utf8Length(item);
    else if (isBytes(item)) total += item.byteLength;
    else if (Array.isArray(item)) { for (const entry of item) { if (!walk(entry, depth + 1)) return false; if (total > limit) return true; } }
    else if (isPlainObject(item)) { for (const [key, entry] of Object.entries(item)) { total += utf8Length(key); if (!walk(entry, depth + 1)) return false; if (total > limit) return true; } }
    else return false;
    return true;
  };
  return walk(value, 0) ? total : null;
}

const OPS: readonly string[] = CAP_OPS;
const KEYS: Record<CapOp, readonly string[]> = {
  "kv.get": ["key"],
  "kv.put": ["key", "body", "contentType", "ifNoneMatch"],
  "kv.list": ["key"],
  "kv.del": ["key"],
  "sql.query": ["db", "sql", "params"],
  "sql.execute": ["db", "sql", "params"],
};

/**
 * Text that goes back to the frame never carries the owner, a token or a stack. Node errors are mapped to a code and a
 * FIXED message (the node's own text names the account, e.g. "Unauthorized Action: tinycloud:pkh:eip155:1:0x…/…"); the
 * one exception is a SQL error, whose SQLite text the app needs to fix its statement, and it is scrubbed: bearer-shaped
 * tokens, `tinycloud:`/`did:` identifiers, account addresses and stack lines are removed, and it is cut short.
 */
function scrub(message: string): string {
  return message
    .replace(/\b(?:tc1|eyJ)[A-Za-z0-9._~+/=-]{12,}/g, "[removed]")
    .replace(/\b(?:tinycloud|did):[^\s'",;)]*/gi, "[removed]")
    .replace(/\b0x[0-9a-fA-F]{40}\b/g, "[removed]")
    .replace(/\n\s*at .*/g, "")
    .slice(0, CAP_MAX_ERROR_CHARS);
}

function fail(code: CapErrorCode, message: string): CapError {
  return capError(code, scrub(message));
}

/** Maps the SDK's error code to the bridge's, with a fixed message (see `scrub`). */
function mapError(error: { readonly code?: string | undefined; readonly message?: string | undefined }): CapError {
  const code = error.code ?? "";
  if (code === "KV_NOT_FOUND" || /NOT_FOUND/.test(code)) return fail("NOT_FOUND", "Not found.");
  if (code === "KV_PRECONDITION_FAILED" || /PRECONDITION/.test(code)) return fail("PRECONDITION_FAILED", "A precondition failed: the key already exists or changed.");
  if (/EXPIRED|SESSION/i.test(code)) return fail("NOT_CONNECTED", "Your session expired: open the app again.");
  if (/UNAUTHORIZED|PERMISSION|FORBIDDEN|AUTH/i.test(code)) return fail("PERMISSION_DENIED", "This app's permissions don't allow that.");
  if (code.startsWith("SQL_") || /SQL/.test(code)) return fail("SQL_ERROR", typeof error.message === "string" && error.message !== "" ? error.message : "The statement failed.");
  return fail("INTERNAL", "The request failed.");
}

const CONTROL = /[\u0000-\u001f\u007f\\]/;

/** A key or database path: no control characters or backslashes, no "." / ".." / empty segment, at most 1024 characters. */
function checkedPath(path: unknown, allowTrailingSlash: boolean): string | undefined {
  if (typeof path !== "string" || path.length === 0 || path.length > CAP_LIMITS.maxPathChars || CONTROL.test(path)) return undefined;
  const segments = path.split("/");
  for (let index = 0; index < segments.length; index += 1) {
    const segment = segments[index];
    if (segment === "" ? !(allowTrailingSlash && index === segments.length - 1 && index > 0) : segment === "." || segment === "..") return undefined;
  }
  return path;
}

interface Prepared {
  readonly run: () => Promise<CapResult>;
}

export function createCapabilityBridge(options: BridgeOptions): CapabilityBridge {
  const limits = { ...CAP_LIMITS, ...options.limits };
  const root = `${options.appId}/`;
  const held = new Set<string>();
  let closed = false;

  const resolve = (path: string): { readonly abs: string; readonly absolute: boolean } => (path.startsWith("/") ? { abs: path.slice(1), absolute: true } : { abs: `${root}${path}`, absolute: false });
  const relative = (abs: string): string => (abs.startsWith(root) ? abs.slice(root.length) : `/${abs}`);

  const deny = (service: string, action: string, path: string): CapError => fail("PERMISSION_DENIED", `This app's permissions don't allow ${service.replace("tinycloud.", "")} ${action} on ${path}.`);

  function prepareKv(op: Extract<CapOp, `kv.${string}`>, args: Record<string, unknown>): Prepared | CapError {
    const rawKey = args["key"];
    const listing = op === "kv.list";
    // `kv.list("")` names the app's own folder; every other key must be a real path.
    const key = listing && rawKey === "" ? "" : checkedPath(typeof rawKey === "string" && rawKey.startsWith("/") ? rawKey.slice(1) : rawKey, listing);
    if (key === undefined) return fail("BAD_REQUEST", `That isn't a valid ${listing ? "prefix" : "key"} for ${op}.`);
    const { abs, absolute } = resolve(typeof rawKey === "string" && rawKey.startsWith("/") ? `/${key}` : key);
    const action: BridgeAction = op === "kv.get" ? "get" : op === "kv.put" ? "put" : op === "kv.list" ? "list" : "del";
    if (!options.authorize("tinycloud.kv", abs, action, absolute)) return deny("tinycloud.kv", action, String(rawKey));
    switch (op) {
      case "kv.get":
        return { run: async () => {
          const result = await options.data.kvGet(abs);
          return result.ok ? { ok: true, bytes: result.data.bytes, ...(result.data.contentType === undefined ? {} : { contentType: result.data.contentType }) } : mapError(result.error);
        } };
      case "kv.put": {
        const body = args["body"];
        const contentType = args["contentType"];
        const ifNoneMatch = args["ifNoneMatch"];
        if (typeof body !== "string" && !isBytes(body)) return fail("BAD_REQUEST", "body must be a string or Uint8Array.");
        if (contentType !== undefined && (typeof contentType !== "string" || contentType.length > 200 || !/^[\x20-\x7e]+$/.test(contentType))) return fail("BAD_REQUEST", "contentType must be plain text.");
        if (ifNoneMatch !== undefined && ifNoneMatch !== true) return fail("BAD_REQUEST", "ifNoneMatch must be true when given.");
        return { run: async () => {
          const result = await options.data.kvPut(abs, body, { contentType: contentType ?? (typeof body === "string" ? "text/plain" : "application/octet-stream"), ifNoneMatch: ifNoneMatch === true });
          return result.ok ? { ok: true } : mapError(result.error);
        } };
      }
      case "kv.list":
        return { run: async () => {
          const result = await options.data.kvList(abs);
          return result.ok ? { ok: true, keys: result.data.keys.map(relative), truncated: result.data.truncated } : mapError(result.error);
        } };
      case "kv.del":
        return { run: async () => {
          const result = await options.data.kvDelete(abs);
          return result.ok ? { ok: true } : mapError(result.error);
        } };
    }
  }

  function prepareSql(op: "sql.query" | "sql.execute", args: Record<string, unknown>): Prepared | CapError {
    const rawDb = args["db"];
    const text = args["sql"];
    const params = args["params"];
    const db = checkedPath(typeof rawDb === "string" && rawDb.startsWith("/") ? rawDb.slice(1) : rawDb, false);
    if (db === undefined) return fail("BAD_REQUEST", "That isn't a valid database name.");
    if (typeof text !== "string" || text.length === 0) return fail("BAD_REQUEST", "The SQL is empty.");
    if (!Array.isArray(params) || params.length > limits.maxParams || !params.every((param) => param === null || typeof param === "string" || typeof param === "boolean" || (typeof param === "number" && Number.isFinite(param)))) {
      return fail("BAD_REQUEST", `params must be an array of at most ${limits.maxParams} strings, numbers, booleans or null.`);
    }
    const bound = params as readonly SqlParam[];
    const statementClass = classifySql(text);
    if (statementClass === null || (op === "sql.query" ? statementClass !== "read" : statementClass === "read")) {
      return fail("BAD_REQUEST", op === "sql.query"
        ? "sql.query runs one read-only statement (SELECT, a read-only WITH, or EXPLAIN). Use sql.execute to change data."
        : "sql.execute runs one INSERT, UPDATE, DELETE, CREATE, DROP or ALTER statement.");
    }
    const absolute = typeof rawDb === "string" && rawDb.startsWith("/");
    if (op === "sql.execute" && absolute) return fail("PERMISSION_DENIED", "An app can change only its own databases.");
    const abs = absolute ? db : `${root}${db}`;
    if (!options.authorize("tinycloud.sql", abs, statementClass, absolute)) return deny("tinycloud.sql", statementClass, String(rawDb));
    return op === "sql.query"
      ? { run: async () => {
        const result = await options.data.sqlQuery(abs, text, bound);
        return result.ok ? { ok: true, columns: result.data.columns, rows: result.data.rows, rowCount: result.data.rowCount } : mapError(result.error);
      } }
      : { run: async () => {
        const result = await options.data.sqlExecute(abs, text, bound);
        return result.ok ? { ok: true, changes: result.data.changes, lastInsertRowId: result.data.lastInsertRowId } : mapError(result.error);
      } };
  }

  function safeReply(id: string, result: CapResult): void {
    if (closed) return;
    try { options.reply(id, result); } catch { /* the frame is gone */ }
  }

  function start(id: string, prepared: Prepared): void {
    held.add(id);
    let replied = false;
    let released = false;
    const answer = (result: CapResult): void => {
      if (replied) return;
      replied = true;
      clearTimeout(soft);
      // A result that would not fit in a message is refused here, not truncated.
      const size = dataSize(result, limits.maxMessageBytes);
      safeReply(id, size === null ? fail("INTERNAL", "The answer could not be sent.") : size > limits.maxMessageBytes ? fail("TOO_LARGE", `The answer is larger than ${limits.maxMessageBytes} bytes: ask for less (for SQL, use LIMIT).`) : result);
    };
    const release = (): void => {
      if (released) return;
      released = true;
      clearTimeout(hard);
      held.delete(id);
    };
    const soft = setTimeout(() => answer(fail("TIMEOUT", "No answer in time. The call may still have been applied: read it back before retrying a write.")), limits.timeoutMs);
    // A call that never settles frees its slot after a hold; until then it still counts against the cap.
    const hard = setTimeout(() => { answer(fail("TIMEOUT", "No answer in time. The call may still have been applied: read it back before retrying a write.")); release(); }, limits.slotHoldMs);
    Promise.resolve().then(prepared.run).then(
      (result) => { answer(result); release(); },
      () => { answer(fail("INTERNAL", "The call failed.")); release(); },
    );
  }

  return {
    handle(request): void {
      let id: string | undefined;
      try {
        if (closed || !isPlainObject(request.body) || typeof request.type !== "string" || !request.type.startsWith(CAP_TYPE_PREFIX)) return;
        const body = request.body;
        // No id, nothing to answer: dropped like any other malformed message.
        if (typeof body["id"] !== "string" || !CAP_ID_PATTERN.test(body["id"]) || Object.keys(body).some((key) => key !== "id" && key !== "args")) return;
        id = body["id"];
        if (held.has(id)) return;
        const op = request.type.slice(CAP_TYPE_PREFIX.length);
        if (!OPS.includes(op)) { safeReply(id, fail("BAD_REQUEST", "Unknown call.")); return; }
        const args = body["args"];
        if (!isPlainObject(args)) { safeReply(id, fail("BAD_REQUEST", "The call's arguments must be a plain object.")); return; }
        const size = dataSize(args, limits.maxMessageBytes);
        if (size === null) { safeReply(id, fail("BAD_REQUEST", "The call's arguments must be plain data.")); return; }
        if (size > limits.maxMessageBytes) { safeReply(id, fail("TOO_LARGE", `The call is larger than ${limits.maxMessageBytes} bytes.`)); return; }
        if (options.isLive?.() === false) { safeReply(id, fail("NOT_CONNECTED", "Your session expired: open the app again.")); return; }
        if (held.size >= limits.maxInFlight) { safeReply(id, fail("BUSY", `More than ${limits.maxInFlight} calls in flight.`)); return; }
        const allowed = KEYS[op as CapOp];
        if (Object.keys(args).some((key) => !allowed.includes(key))) { safeReply(id, fail("BAD_REQUEST", `Unexpected argument for ${op}.`)); return; }
        const prepared = op.startsWith("kv.") ? prepareKv(op as Extract<CapOp, `kv.${string}`>, args) : prepareSql(op as "sql.query" | "sql.execute", args);
        if ("run" in prepared) start(id, prepared); else safeReply(id, prepared);
      } catch {
        if (id !== undefined) safeReply(id, fail("INTERNAL", "The call failed."));
      }
    },
    inFlight: () => held.size,
    close(): void {
      closed = true;
    },
  };
}
