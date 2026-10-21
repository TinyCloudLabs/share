import { readFileSync } from "node:fs";
import { join } from "node:path";
import * as sdkCore from "@tinycloud/sdk-core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { CAP_LIMITS, CAP_OPS, type CapResult } from "../src/artifact/jsx-runtime/cap-protocol.ts";
import { type AppData, type PortResult, createCapabilityBridge, dataSize } from "../src/apps/bridge.ts";
import { type CatalogEntry, catalog } from "../src/apps/catalog.ts";
import { type ManifestSdk, makeAuthorizer } from "../src/apps/grants.ts";

const sdk: ManifestSdk = sdkCore;
const HEALTH = "xyz.tinycloud.sample.healthlog";
const RECIPES = "xyz.tinycloud.sample.recipes";
const entryOf = (appId: string): CatalogEntry => {
  const found = catalog.apps.find((entry) => entry.app_id === appId);
  if (found === undefined) throw new Error(`no ${appId}`);
  return found;
};
const manifestOf = (appId: string): sdkCore.Manifest => {
  const entry = entryOf(appId);
  return sdkCore.validateManifest(JSON.parse(readFileSync(join("public", entry.bundle.root, entry.manifest.path), "utf8")));
};

const ok = <T>(data: T): PortResult<T> => ({ ok: true, data });
const refused = (code: string, message = "refused"): PortResult<never> => ({ ok: false, error: { code, message } });

/** A data port that records every call; `override` replaces single methods. */
function fakeData(override: Partial<AppData> = {}): { data: AppData; calls: string[] } {
  const calls: string[] = [];
  const data: AppData = {
    kvGet: async (path) => { calls.push(`kv.get ${path}`); return ok({ bytes: new TextEncoder().encode("hello"), contentType: "text/plain" }); },
    kvPut: async (path, _body, options) => { calls.push(`kv.put ${path} ${options.contentType} ${options.ifNoneMatch}`); return ok(undefined); },
    kvList: async (prefix) => { calls.push(`kv.list ${prefix}`); return ok({ keys: [`${prefix}a.json`, "other-app/x"], truncated: false }); },
    kvDelete: async (path) => { calls.push(`kv.del ${path}`); return ok(undefined); },
    sqlQuery: async (db, text) => { calls.push(`sql.query ${db} ${text}`); return ok({ columns: ["n"], rows: [[1]], rowCount: 1 }); },
    sqlExecute: async (db, text) => { calls.push(`sql.execute ${db} ${text}`); return ok({ changes: 1, lastInsertRowId: 7 }); },
    ...override,
  };
  return { data, calls };
}

interface Harness {
  readonly replies: { id: string; result: CapResult }[];
  readonly calls: string[];
  send(op: string, args: unknown, id?: string): void;
  call(op: string, args: unknown): Promise<CapResult>;
  bridge: ReturnType<typeof createCapabilityBridge>;
}

function harness(appId: string, override: Partial<AppData> = {}, extra: Partial<Parameters<typeof createCapabilityBridge>[0]> = {}, manifest: sdkCore.Manifest = manifestOf(appId)): Harness {
  const { data, calls } = fakeData(override);
  const replies: { id: string; result: CapResult }[] = [];
  const bridge = createCapabilityBridge({ appId, authorize: makeAuthorizer(manifest, sdk), data, reply: (id, result) => { replies.push({ id, result }); }, ...extra });
  let counter = 0;
  const send = (op: string, args: unknown, id = String((counter += 1))): void => bridge.handle({ type: `cap/${op}`, body: { id, args } });
  const call = async (op: string, args: unknown): Promise<CapResult> => {
    const id = String((counter += 1000));
    send(op, args, id);
    await vi.waitFor(() => { if (!replies.some((reply) => reply.id === id)) throw new Error("no reply yet"); });
    return replies.find((reply) => reply.id === id)!.result;
  };
  return { replies, calls, send, call, bridge };
}

const code = (result: CapResult): string => (result.ok ? "ok" : result.error.code);

describe("bridge: the operations an app can use", () => {
  it("kv: get/put/list/del are relative to <app_id>/ and answer in the contract's shapes", async () => {
    // The sample manifests never delete, so this app's copy adds a scratch folder that may.
    const health = manifestOf(HEALTH);
    const h = harness(HEALTH, {}, {}, { ...health, permissions: [...(health.permissions ?? []), { service: "tinycloud.kv", path: "prefs/", actions: ["del"] }] });
    const got = await h.call("kv.get", { key: "prefs/goals.json" });
    expect(got).toEqual({ ok: true, bytes: new TextEncoder().encode("hello"), contentType: "text/plain" });
    expect(await h.call("kv.put", { key: "prefs/goals.json", body: '{"kcal":2000}', contentType: "application/json" })).toEqual({ ok: true });
    expect(await h.call("kv.put", { key: "prefs/photo.bin", body: new Uint8Array([1, 2, 3]), ifNoneMatch: true })).toEqual({ ok: true });
    expect(await h.call("kv.list", { key: "knowledge/" })).toEqual({ ok: true, keys: ["knowledge/a.json", `/other-app/x`], truncated: false });
    expect(await h.call("kv.del", { key: "prefs/goals.json" })).toEqual({ ok: true });
    expect(h.calls).toEqual([
      `kv.get ${HEALTH}/prefs/goals.json`,
      `kv.put ${HEALTH}/prefs/goals.json application/json false`,
      `kv.put ${HEALTH}/prefs/photo.bin application/octet-stream true`,
      `kv.list ${HEALTH}/knowledge/`,
      `kv.del ${HEALTH}/prefs/goals.json`,
    ]);
  });

  it("sql: query is read-only, execute writes or changes schema, both inside the app's own database", async () => {
    const h = harness(HEALTH);
    expect(await h.call("sql.query", { db: "healthlog", sql: "SELECT 1 AS n", params: [] })).toEqual({ ok: true, columns: ["n"], rows: [[1]], rowCount: 1 });
    expect(await h.call("sql.execute", { db: "healthlog", sql: "INSERT INTO meal (name) VALUES (?)", params: ["x"] })).toEqual({ ok: true, changes: 1, lastInsertRowId: 7 });
    expect(await h.call("sql.execute", { db: "healthlog", sql: "CREATE TABLE IF NOT EXISTS t (a)", params: [] })).toMatchObject({ ok: true });
    expect(h.calls).toEqual([
      `sql.query ${HEALTH}/healthlog SELECT 1 AS n`,
      `sql.execute ${HEALTH}/healthlog INSERT INTO meal (name) VALUES (?)`,
      `sql.execute ${HEALTH}/healthlog CREATE TABLE IF NOT EXISTS t (a)`,
    ]);
  });

  it("the recipes sample reads the Health Log database through its whole-database grant, and only reads", async () => {
    const h = harness(RECIPES);
    expect(await h.call("sql.query", { db: `/${HEALTH}/healthlog`, sql: "SELECT id, name FROM meal WHERE id = ?", params: [3] })).toMatchObject({ ok: true });
    expect(h.calls).toEqual([`sql.query ${HEALTH}/healthlog SELECT id, name FROM meal WHERE id = ?`]);
    for (const text of ["INSERT INTO meal (name) VALUES ('x')", "UPDATE meal SET kcal = 1", "DELETE FROM meal", "DROP TABLE meal", "CREATE TABLE sneaky (a)"]) {
      const result = await h.call("sql.execute", { db: `/${HEALTH}/healthlog`, sql: text, params: [] });
      expect(code(result), text).toBe("PERMISSION_DENIED");
    }
    expect(h.calls).toHaveLength(1);
  });
});

describe("bridge: the parent's manifest check, before any SDK call", () => {
  it("kv.get outside the manifest is PERMISSION_DENIED and never reaches the port", async () => {
    const h = harness(HEALTH);
    for (const key of ["secrets/x", "app/../prefs/x", "photos/a.jpg", "/xyz.tinycloud.sample.recipes/prefs/a.json", `/${HEALTH}/prefs/goals.json`, "/vault/keys"]) {
      const result = await h.call("kv.get", { key });
      expect(["PERMISSION_DENIED", "BAD_REQUEST"], `${key}: ${JSON.stringify(result)}`).toContain(code(result));
    }
    expect(code(await h.call("kv.get", { key: "photos/a.jpg" }))).toBe("PERMISSION_DENIED");
    expect(code(await h.call("kv.list", { key: "" }))).toBe("PERMISSION_DENIED");
    expect(code(await h.call("kv.put", { key: "app/app.jsx", body: "x" }))).toBe("PERMISSION_DENIED");
    expect(code(await h.call("kv.del", { key: "app/app.jsx" }))).toBe("PERMISSION_DENIED");
    expect(code(await h.call("kv.del", { key: "knowledge/index.md" }))).toBe("PERMISSION_DENIED");
    expect(h.calls).toEqual([]);
  });

  it("account, registry and capability calls are not bridge operations: they never reach the port", async () => {
    const h = harness(HEALTH);
    const args = { key: "k", value: "v", db: "x", sql: "SELECT 1", params: [] };
    for (const op of ["registry.list", "account.get", "capabilities.list", "capabilities.grant", "cap/kv.put"]) {
      expect(code(await h.call(op, args)), op).toBe("BAD_REQUEST");
    }
    expect(h.calls).toEqual([]);
  });

  it("another app's files are reachable only where the manifest has a cross-app grant, by absolute path", async () => {
    const h = harness(HEALTH);
    expect(code(await h.call("kv.get", { key: `/${RECIPES}/prefs/settings.json` }))).toBe("PERMISSION_DENIED");
    expect(code(await h.call("sql.query", { db: `/${RECIPES}/recipes`, sql: "SELECT 1", params: [] }))).toBe("PERMISSION_DENIED");
    expect(code(await h.call("sql.query", { db: `${RECIPES}/recipes`, sql: "SELECT 1", params: [] }))).toBe("PERMISSION_DENIED");
    expect(h.calls).toEqual([]);
  });

  it("sql.execute never leaves the app's own database, even where the manifest could read elsewhere", async () => {
    const h = harness(RECIPES);
    expect(code(await h.call("sql.execute", { db: `/${RECIPES}/recipes`, sql: "DELETE FROM recipe", params: [] }))).toBe("PERMISSION_DENIED");
    expect(code(await h.call("sql.execute", { db: `/${HEALTH}/healthlog`, sql: "DELETE FROM meal", params: [] }))).toBe("PERMISSION_DENIED");
    expect(code(await h.call("sql.execute", { db: "elsewhere", sql: "DELETE FROM meal", params: [] }))).toBe("PERMISSION_DENIED");
    expect(h.calls).toEqual([]);
  });

  it("the statement class picks the ability: DDL needs schema, writes need write, reads need read", async () => {
    const manifest = manifestOf(HEALTH);
    const readWriteOnly: sdkCore.Manifest = { ...manifest, permissions: [{ service: "tinycloud.sql", path: "healthlog", actions: ["read", "write"] }] };
    const { data, calls } = fakeData();
    const replies: CapResult[] = [];
    const bridge = createCapabilityBridge({ appId: HEALTH, authorize: makeAuthorizer(readWriteOnly, sdk), data, reply: (_id, result) => { replies.push(result); } });
    const run = async (op: string, text: string, id: string): Promise<CapResult> => {
      replies.length = 0;
      bridge.handle({ type: `cap/${op}`, body: { id, args: { db: "healthlog", sql: text, params: [] } } });
      await vi.waitFor(() => { if (replies.length === 0) throw new Error("wait"); });
      return replies[0]!;
    };
    // TC-1581: the node would run DDL on a write grant. The bridge does not.
    expect(code(await run("sql.execute", "DROP TABLE meal", "1"))).toBe("PERMISSION_DENIED");
    expect(code(await run("sql.execute", "CREATE TABLE x (a)", "2"))).toBe("PERMISSION_DENIED");
    expect(code(await run("sql.execute", "WITH x AS (SELECT 1) INSERT INTO meal (kcal) SELECT * FROM x", "3"))).toBe("ok");
    expect(code(await run("sql.query", "SELECT 1", "4"))).toBe("ok");
    expect(calls).toHaveLength(2);
  });

  it("the frame cannot name another service, a delegation, a space or a session", async () => {
    const h = harness(HEALTH);
    for (const op of ["vault.get", "delegation.create", "kv.get/../../x", "secrets.read", "session", "capabilities.read", "duckdb.query", "../kv.get", ""]) {
      const result = await h.call(op, { key: "prefs/x" });
      expect(code(result), op).toBe("BAD_REQUEST");
    }
    for (const extra of [{ service: "tinycloud.vault" }, { space: "secrets" }, { delegation: "x" }, { host: "https://evil.example" }, { did: "did:key:abc" }]) {
      expect(code(await h.call("kv.get", { key: "prefs/goals.json", ...extra })), JSON.stringify(extra)).toBe("BAD_REQUEST");
    }
    expect(h.calls).toEqual([]);
  });
});

describe("bridge: SQL the classifier refuses never reaches the port", () => {
  const refusedByClassifier = [
    "DROP TABLE meal",
    "SELECT 1; DROP TABLE meal",
    "SELECT 1; SELECT 2",
    "ATTACH DATABASE 'x' AS y",
    "PRAGMA writable_schema=1",
    "VACUUM",
    "SELECT load_extension('x')",
    'SELECT "load_extension"(\'x\')',
    "WITH x AS (SELECT 1) INSERT INTO meal (kcal) SELECT * FROM x",
    "DELETE FROM meal",
    "INSERT INTO meal (name) VALUES ('x')",
    "SELECT 1;\u00a0DROP TABLE meal",
    "",
  ];
  it("sql.query accepts one read-only statement", async () => {
    const h = harness(HEALTH);
    for (const text of refusedByClassifier) expect(code(await h.call("sql.query", { db: "healthlog", sql: text, params: [] })), text).toBe("BAD_REQUEST");
    expect(h.calls).toEqual([]);
  });

  it("sql.execute accepts one write or schema statement", async () => {
    const h = harness(HEALTH);
    for (const text of ["SELECT 1", "SELECT 1; DROP TABLE meal", "ATTACH DATABASE 'x' AS y", "PRAGMA writable_schema=1", "VACUUM", "SELECT load_extension('x')", "BEGIN", "WITH x AS (SELECT 1) SELECT * FROM x"]) {
      expect(code(await h.call("sql.execute", { db: "healthlog", sql: text, params: [] })), text).toBe("BAD_REQUEST");
    }
    expect(h.calls).toEqual([]);
  });

  it("params are plain scalars, bounded", async () => {
    const h = harness(HEALTH);
    for (const params of [[{}], [[1]], [undefined], [Number.NaN], [Number.POSITIVE_INFINITY], "x", null, { 0: 1 }, new Array(CAP_LIMITS.maxParams + 1).fill(1)]) {
      expect(code(await h.call("sql.query", { db: "healthlog", sql: "SELECT ?", params })), JSON.stringify(params)?.slice(0, 40)).toBe("BAD_REQUEST");
    }
    expect(code(await h.call("sql.query", { db: "healthlog", sql: "SELECT ?, ?, ?, ?", params: ["a", 1, true, null] }))).toBe("ok");
  });
});

describe("bridge: paths", () => {
  it.each([
    ["", "kv.get"],
    ["prefs/", "kv.get"],
    ["prefs//goals.json", "kv.get"],
    ["prefs/./goals.json", "kv.get"],
    ["prefs/../prefs/goals.json", "kv.get"],
    ["prefs\\goals.json", "kv.get"],
    ["prefs/go\u0000als.json", "kv.get"],
    ["prefs/go\nals.json", "kv.put"],
    [`prefs/${"a".repeat(2000)}`, "kv.del"],
    ["/", "kv.get"],
    ["//xyz", "kv.get"],
  ])("refuses the key %j for %s", async (key, op) => {
    const h = harness(HEALTH);
    expect(code(await h.call(op, op === "kv.put" ? { key, body: "x" } : { key }))).toBe("BAD_REQUEST");
    expect(h.calls).toEqual([]);
  });

  it("refuses a non-string key or database, and a leading-slash database that is not a database path", async () => {
    const h = harness(HEALTH);
    for (const key of [1, null, undefined, {}, ["a"]]) expect(code(await h.call("kv.get", { key }))).toBe("BAD_REQUEST");
    for (const db of [1, null, "", "..", "a/../b", "/", "x\u0000"]) expect(code(await h.call("sql.query", { db, sql: "SELECT 1", params: [] }))).toBe("BAD_REQUEST");
    expect(h.calls).toEqual([]);
  });

  it("kv.put options are checked", async () => {
    const h = harness(HEALTH);
    for (const extra of [{ contentType: 5 }, { contentType: "text/plain\r\nx-evil: 1" }, { contentType: "é" }, { contentType: "a".repeat(201) }, { ifNoneMatch: false }, { ifNoneMatch: "*" }]) {
      expect(code(await h.call("kv.put", { key: "prefs/a", body: "x", ...extra })), JSON.stringify(extra)).toBe("BAD_REQUEST");
    }
    for (const body of [5, null, { a: 1 }, ["x"], undefined]) expect(code(await h.call("kv.put", { key: "prefs/a", body }))).toBe("BAD_REQUEST");
    expect(h.calls).toEqual([]);
  });
});

describe("bridge: size, concurrency, time", () => {
  beforeEach(() => { vi.useFakeTimers(); });
  afterEach(() => { vi.useRealTimers(); });

  const hang = (): { data: Partial<AppData>; settle: () => void; started: () => number } => {
    const waiters: (() => void)[] = [];
    const wait = (): Promise<PortResult<never>> => new Promise((resolve) => { waiters.push(() => resolve(refused("KV_NOT_FOUND"))); });
    return { data: { kvGet: wait }, settle: () => { for (const done of waiters.splice(0)) done(); }, started: () => waiters.length };
  };

  it("an oversize call is TOO_LARGE and never reaches the port; just under the cap passes", async () => {
    const h = harness(HEALTH);
    const big = "x".repeat(CAP_LIMITS.maxMessageBytes + 1);
    h.send("kv.put", { key: "prefs/a", body: big }, "1");
    h.send("kv.put", { key: "prefs/a", body: new Uint8Array(CAP_LIMITS.maxMessageBytes + 1) }, "2");
    h.send("sql.execute", { db: "healthlog", sql: "INSERT INTO meal (name) VALUES (?)", params: [big] }, "3");
    // Counted as UTF-8: a string of 400 000 three-byte characters is 1.2 MB.
    h.send("kv.put", { key: "prefs/a", body: "€".repeat(400_000) }, "4");
    await vi.advanceTimersByTimeAsync(0);
    expect(h.replies.map((reply) => code(reply.result))).toEqual(["TOO_LARGE", "TOO_LARGE", "TOO_LARGE", "TOO_LARGE"]);
    expect(h.calls).toEqual([]);
    h.send("kv.put", { key: "prefs/a", body: "x".repeat(CAP_LIMITS.maxMessageBytes - 100) }, "5");
    await vi.advanceTimersByTimeAsync(0);
    expect(h.calls).toHaveLength(1);
  });

  it("an answer larger than the cap is TOO_LARGE, not truncated", async () => {
    const h = harness(HEALTH, { kvGet: async () => ok({ bytes: new Uint8Array(CAP_LIMITS.maxMessageBytes + 1) }) });
    h.send("kv.get", { key: "prefs/a" }, "1");
    await vi.advanceTimersByTimeAsync(0);
    expect(code(h.replies[0]!.result)).toBe("TOO_LARGE");
  });

  it("the fifth call in flight is BUSY, not queued; a settled call frees its slot", async () => {
    const stuck = hang();
    const h = harness(HEALTH, stuck.data);
    for (let id = 1; id <= 5; id += 1) h.send("kv.get", { key: `prefs/${id}` }, String(id));
    await vi.advanceTimersByTimeAsync(0);
    expect(stuck.started()).toBe(CAP_LIMITS.maxInFlight);
    expect(h.replies.map((reply) => [reply.id, code(reply.result)])).toEqual([["5", "BUSY"]]);
    expect(h.bridge.inFlight()).toBe(4);
    stuck.settle();
    await vi.advanceTimersByTimeAsync(0);
    expect(h.replies.filter((reply) => reply.id !== "5").map((reply) => code(reply.result))).toEqual(["NOT_FOUND", "NOT_FOUND", "NOT_FOUND", "NOT_FOUND"]);
    expect(h.bridge.inFlight()).toBe(0);
    h.send("kv.get", { key: "prefs/6" }, "6");
    await vi.advanceTimersByTimeAsync(0);
    expect(stuck.started()).toBe(1);
  });

  it("a call that takes too long is TIMEOUT and says it may have been applied; its slot is held until it settles", async () => {
    const stuck = hang();
    const h = harness(HEALTH, stuck.data);
    h.send("kv.get", { key: "prefs/1" }, "1");
    await vi.advanceTimersByTimeAsync(CAP_LIMITS.timeoutMs - 1);
    expect(h.replies).toEqual([]);
    await vi.advanceTimersByTimeAsync(1);
    expect(h.replies).toHaveLength(1);
    const result = h.replies[0]!.result;
    expect(code(result)).toBe("TIMEOUT");
    expect(result.ok ? "" : result.error.message).toMatch(/may still have been applied/);
    expect(h.bridge.inFlight()).toBe(1);
    // A late answer is dropped: the frame already has its TIMEOUT.
    stuck.settle();
    await vi.advanceTimersByTimeAsync(0);
    expect(h.replies).toHaveLength(1);
    expect(h.bridge.inFlight()).toBe(0);
  });

  it("a call that never settles frees its slot after the hold, so an app cannot be locked out for good", async () => {
    const stuck = hang();
    const h = harness(HEALTH, stuck.data);
    for (let id = 1; id <= 4; id += 1) h.send("kv.get", { key: `prefs/${id}` }, String(id));
    await vi.advanceTimersByTimeAsync(CAP_LIMITS.timeoutMs);
    expect(h.replies).toHaveLength(4);
    h.send("kv.get", { key: "prefs/5" }, "5");
    await vi.advanceTimersByTimeAsync(0);
    expect(code(h.replies.at(-1)!.result)).toBe("BUSY");
    await vi.advanceTimersByTimeAsync(CAP_LIMITS.slotHoldMs);
    expect(h.bridge.inFlight()).toBe(0);
    h.send("kv.get", { key: "prefs/6" }, "6");
    await vi.advanceTimersByTimeAsync(0);
    expect(stuck.started()).toBe(5);
  });

  it("a repeated request id while the first is running is dropped, and a closed bridge answers nothing", async () => {
    const stuck = hang();
    const h = harness(HEALTH, stuck.data);
    h.send("kv.get", { key: "prefs/1" }, "1");
    h.send("kv.get", { key: "prefs/1" }, "1");
    await vi.advanceTimersByTimeAsync(0);
    expect(stuck.started()).toBe(1);
    h.bridge.close();
    stuck.settle();
    h.send("kv.get", { key: "prefs/2" }, "2");
    await vi.advanceTimersByTimeAsync(CAP_LIMITS.timeoutMs);
    expect(h.replies).toEqual([]);
  });

  it("after the session ends every call is NOT_CONNECTED", async () => {
    let live = true;
    const h = harness(HEALTH, {}, { isLive: () => live });
    expect(code(await Promise.resolve().then(async () => { h.send("kv.get", { key: "prefs/a" }, "1"); await vi.advanceTimersByTimeAsync(0); return h.replies[0]!.result; }))).toBe("ok");
    live = false;
    h.send("kv.get", { key: "prefs/a" }, "2");
    await vi.advanceTimersByTimeAsync(0);
    const result = h.replies[1]!.result;
    expect(code(result)).toBe("NOT_CONNECTED");
    expect(result.ok ? "" : result.error.message).toBe("Your session expired: open the app again.");
  });
});

describe("bridge: it never throws into the frame", () => {
  it("answers a result, or drops what has no id, for every malformed request", async () => {
    const h = harness(HEALTH);
    const circular: Record<string, unknown> = { key: "prefs/a" };
    circular["self"] = circular;
    const throwing = { get key(): string { throw new Error("getter"); } };
    const requests: { type: unknown; body: unknown }[] = [
      { type: "cap/kv.get", body: undefined },
      { type: "cap/kv.get", body: null },
      { type: "cap/kv.get", body: "x" },
      { type: "cap/kv.get", body: [] },
      { type: "cap/kv.get", body: { id: 1, args: {} } },
      { type: "cap/kv.get", body: { id: "x1", args: {} } },
      { type: "cap/kv.get", body: { id: "1", args: null } },
      { type: "cap/kv.get", body: { id: "1", args: [] } },
      { type: "cap/kv.get", body: { id: "1", args: {}, extra: true } },
      { type: "cap/kv.get", body: { id: "1", args: circular } },
      { type: "cap/kv.get", body: { id: "1", args: throwing } },
      { type: "cap/kv.get", body: { id: "1", args: { key: "a", fn: () => 1 } } },
      { type: "cap/kv.get", body: { id: "1", args: { key: new Date() } } },
      { type: "cap/kv.get", body: { id: "1", args: { key: { a: { b: { c: { d: { e: { f: { g: 1 } } } } } } } } } },
      { type: 5, body: { id: "1", args: {} } },
      { type: "kv.get", body: { id: "1", args: {} } },
      { type: Symbol.iterator, body: { id: "1", args: {} } },
    ];
    for (const request of requests) expect(() => h.bridge.handle(request as { type: string; body: unknown })).not.toThrow();
    for (let turn = 0; turn < 5; turn += 1) await Promise.resolve();
    for (const reply of h.replies) expect(reply.result.ok).toBe(false);
    expect(h.calls).toEqual([]);
  });

  it("maps a port that throws or rejects to INTERNAL, and a reply function that throws is contained", async () => {
    const h = harness(HEALTH, { kvGet: async () => { throw new Error("socket closed"); }, kvDelete: () => { throw new Error("sync boom"); } });
    expect(code(await h.call("kv.get", { key: "prefs/a" }))).toBe("INTERNAL");
    expect(code(await h.call("kv.put", { key: "knowledge/a.md", body: "x" }))).toBe("ok");
    const broken = createCapabilityBridge({ appId: HEALTH, authorize: makeAuthorizer(manifestOf(HEALTH), sdk), data: fakeData().data, reply: () => { throw new Error("frame gone"); } });
    expect(() => broken.handle({ type: "cap/kv.get", body: { id: "1", args: { key: "prefs/a" } } })).not.toThrow();
    for (let turn = 0; turn < 5; turn += 1) await Promise.resolve();
  });

  it("maps the SDK's error codes and never passes token-shaped text back", async () => {
    const answers: Record<string, [string, string]> = {
      KV_NOT_FOUND: ["NOT_FOUND", "gone"],
      KV_PRECONDITION_FAILED: ["PRECONDITION_FAILED", "exists"],
      AUTH_UNAUTHORIZED: ["PERMISSION_DENIED", "no"],
      SQL_ERROR: ["SQL_ERROR", "syntax error"],
      SQL_EXECUTION_FAILED: ["SQL_ERROR", "x"],
      SESSION_EXPIRED: ["NOT_CONNECTED", "x"],
      NETWORK_ERROR: ["INTERNAL", "offline"],
      "": ["INTERNAL", "x"],
    };
    for (const [sdkCode, [expected]] of Object.entries(answers)) {
      const h = harness(HEALTH, { kvGet: async () => refused(sdkCode, "message") });
      expect(code(await h.call("kv.get", { key: "prefs/a" })), sdkCode).toBe(expected);
    }
    const token = `tc1${"A".repeat(40)} eyJ${"b".repeat(30)}.payload`;
    const h = harness(HEALTH, { kvGet: async () => refused("NETWORK_ERROR", `failed for ${token} ${"z".repeat(900)}`) });
    const result = await h.call("kv.get", { key: "prefs/a" });
    const message = result.ok ? "" : result.error.message;
    expect(message).not.toMatch(/tc1A|eyJb/);
    expect(message.length).toBeLessThanOrEqual(500);
  });
});

describe("dataSize", () => {
  it("measures plain data and refuses anything else", () => {
    expect(dataSize({ a: "é", b: new Uint8Array(10), c: [1, 2, true, null] }, 1000)).toBe(1 + 2 + 1 + 10 + 1 + 8 * 4);
    for (const value of [() => 1, new Date(), new Map(), Symbol("x"), 10n, Number.NaN, Object.create({ inherited: 1 }), { a: new Set() }]) expect(dataSize(value, 1000)).toBeNull();
    const deep: unknown[] = [];
    let cursor = deep;
    for (let level = 0; level < 20; level += 1) { const next: unknown[] = []; cursor.push(next); cursor = next; }
    expect(dataSize(deep, 1000)).toBeNull();
  });

  it("every operation name in the contract has a key set", () => {
    expect([...CAP_OPS]).toEqual(["kv.get", "kv.put", "kv.list", "kv.del", "sql.query", "sql.execute"]);
  });
});

describe("bridge: sql.execute never leaves the app's own databases, whatever the manifest grants", () => {
  it("a manifest with a skipPrefix WRITE and SCHEMA grant on another app's database still cannot execute there", async () => {
    const recipes = manifestOf(RECIPES);
    const greedy: sdkCore.Manifest = { ...recipes, permissions: [...(recipes.permissions ?? []), { service: "tinycloud.sql", path: `${HEALTH}/healthlog`, actions: ["write", "schema"], skipPrefix: true }] };
    const authorize = makeAuthorizer(greedy, sdk);
    // The manifest check alone would allow it: this is what the rule in bridge.ts has to catch.
    expect(authorize("tinycloud.sql", `${HEALTH}/healthlog`, "write", true)).toBe(true);
    expect(authorize("tinycloud.sql", `${HEALTH}/healthlog`, "schema", true)).toBe(true);
    const h = harness(RECIPES, {}, {}, greedy);
    for (const text of ["DELETE FROM meal", "INSERT INTO meal (name) VALUES ('x')", "DROP TABLE meal", "CREATE TABLE sneaky (a)"]) {
      const result = await h.call("sql.execute", { db: `/${HEALTH}/healthlog`, sql: text, params: [] });
      expect(code(result), text).toBe("PERMISSION_DENIED");
      expect(result.ok ? "" : result.error.message).toBe("An app can change only its own databases.");
    }
    expect(h.calls).toEqual([]);
    // Reading there is what the manifest granted, and still works; its own database still takes writes.
    expect(code(await h.call("sql.query", { db: `/${HEALTH}/healthlog`, sql: "SELECT 1", params: [] }))).toBe("ok");
    expect(code(await h.call("sql.execute", { db: "recipes", sql: "DELETE FROM recipe", params: [] }))).toBe("ok");
  });
});

describe("bridge: what the node says never reaches the frame", () => {
  const OWNER = "0x1234567890abcdef1234567890ABCDEF12345678";
  const nodeRefusal = `401 - Unauthorized Action: tinycloud:pkh:eip155:1:${OWNER}:applications/kv/${HEALTH}/prefs/x / tinycloud.kv/get`;
  const ports = (message: string, sdkCode = "AUTH_UNAUTHORIZED"): Partial<AppData> => ({
    kvGet: async () => ({ ok: false, error: { code: sdkCode, message } }),
    kvPut: async () => ({ ok: false, error: { code: sdkCode, message } }),
    sqlQuery: async () => ({ ok: false, error: { code: sdkCode, message } }),
  });

  it("a node refusal becomes a code and a fixed message: no account, no identifier, no path", async () => {
    const h = harness(HEALTH, ports(nodeRefusal));
    const result = await h.call("kv.get", { key: "prefs/goals.json" });
    expect(result).toEqual({ ok: false, error: { code: "PERMISSION_DENIED", message: "This app's permissions don't allow that." } });
    expect(JSON.stringify(result)).not.toMatch(/0x[0-9a-f]{40}|tinycloud:|did:|eip155/i);
  });

  it.each([
    ["KV_NOT_FOUND", "NOT_FOUND", "Not found."],
    ["KV_PRECONDITION_FAILED", "PRECONDITION_FAILED", "A precondition failed: the key already exists or changed."],
    ["SESSION_EXPIRED", "NOT_CONNECTED", "Your session expired: open the app again."],
    ["NETWORK_ERROR", "INTERNAL", "The request failed."],
    ["WHATEVER", "INTERNAL", "The request failed."],
  ])("%s -> %s with fixed text, whatever the node wrote", async (sdkCode, expectedCode, expectedMessage) => {
    const h = harness(HEALTH, ports(`${nodeRefusal}\n    at fetch (https://node/x.js:1:1)`, sdkCode));
    const result = await h.call("kv.get", { key: "prefs/goals.json" });
    expect(result).toEqual({ ok: false, error: { code: expectedCode, message: expectedMessage } });
  });

  it("a SQL error keeps SQLite's own words (the app needs them) with any identifier, account or stack removed", async () => {
    const h = harness(HEALTH, ports(`SQLite error: no such table: meal in ${nodeRefusal} did:pkh:eip155:1:${OWNER}\n    at run (x.js:1:1)`, "SQL_ERROR"));
    const result = await h.call("sql.query", { db: "healthlog", sql: "SELECT * FROM meal", params: [] });
    expect(code(result)).toBe("SQL_ERROR");
    const message = result.ok ? "" : result.error.message;
    expect(message).toContain("no such table: meal");
    expect(message).not.toMatch(/0x[0-9a-f]{40}|tinycloud:pkh|did:|\n|\bat run\b/i);
  });

  it("a port that throws gives a fixed message, not the exception's text", async () => {
    const h = harness(HEALTH, { kvGet: async () => { throw new Error(`socket closed for ${OWNER}`); } });
    const result = await h.call("kv.get", { key: "prefs/goals.json" });
    expect(result).toEqual({ ok: false, error: { code: "INTERNAL", message: "The call failed." } });
  });
});
