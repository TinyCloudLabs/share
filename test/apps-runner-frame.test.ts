import { createHash, webcrypto } from "node:crypto";
import { readFileSync } from "node:fs";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { kv, sql } from "../src/artifact/jsx-runtime/app-module.ts";
import { CAP_LIMITS, CAP_OPS, CAP_TYPES, type CapResult } from "../src/artifact/jsx-runtime/cap-protocol.ts";
import { JSX_LIBRARY_SET, JSX_MODULE_SPECS, JSX_RUNNER_ONLY_IDS, type JsxManifest, fileIdForSpecifier } from "../src/artifact/jsx-runtime/files.ts";
import { JSX_BRIDGE_RUNTIME_SCRIPT, buildCapabilityReply, parseCapabilityMessage } from "../src/viewer/jsx-frame.ts";
import { loadJsxModules, requiredFileIds } from "../src/viewer/jsx-modules.ts";
import { renderJsxPage } from "../src/viewer/jsx-render.ts";
import { createJsxSandbox } from "../src/viewer/jsx-sandbox.ts";

Object.defineProperty(globalThis, "crypto", { value: webcrypto, configurable: true });

const NONCE_OF = (iframe: HTMLIFrameElement): string => new URL(iframe.src).hash.slice(1);

describe("the @tinycloud/app module is for the installed-app runner only", () => {
  const files = ["react", "react-dom", "runtime", "tailwind", "tinycloud-app", "lucide-react"];
  const text = (id: string): string => `__TC_DEFINE__(["${id}"],function(){});`;
  const sha = (value: string): string => createHash("sha256").update(value, "utf8").digest("hex");
  const manifest: JsxManifest = {
    version: 1,
    files: Object.fromEntries(files.map((id) => [id, { id, url: `/assets/jsx-runtime/${id}.js`, sha256: sha(text(id)), bytes: text(id).length, provides: id === "tinycloud-app" ? ["@tinycloud/app"] : [id] }])),
  };
  const fetchImpl = (async (url: string) => new Response(text(/jsx-runtime\/(.+)\.js$/.exec(url)![1]!), { status: 200 })) as unknown as typeof fetch;
  const source = 'import { sql, kv } from "@tinycloud/app";\nexport default () => null;';

  it("is declared runner-only, and is not offered in the shared viewer's library list", () => {
    expect(JSX_RUNNER_ONLY_IDS).toEqual(["tinycloud-app"]);
    expect(JSX_MODULE_SPECS.find((spec) => spec.id === "tinycloud-app")).toMatchObject({ provides: ["@tinycloud/app"], always: false, runnerOnly: true });
    expect(JSX_LIBRARY_SET).not.toContain("@tinycloud/app");
  });

  it("the share viewer never loads it, so an imported @tinycloud/app is an unknown library there", async () => {
    expect(fileIdForSpecifier(manifest, "@tinycloud/app")).toBeUndefined();
    expect(requiredFileIds(manifest, ["@tinycloud/app"])).not.toContain("tinycloud-app");
    expect(Object.keys(await loadJsxModules(manifest, source, { fetch: fetchImpl }))).not.toContain("tinycloud-app");
  });

  it("the runner loads it, verified like any other module", async () => {
    expect(fileIdForSpecifier(manifest, "@tinycloud/app", true)).toBe("tinycloud-app");
    const modules = await loadJsxModules(manifest, source, { fetch: fetchImpl, allowRunnerModules: true });
    expect(Object.keys(modules).sort()).toEqual(["react", "react-dom", "runtime", "tailwind", "tinycloud-app"]);
    const tampered = (async (url: string) => new Response(/tinycloud-app/.test(url) ? "__TC_DEFINE__(['@tinycloud/app'],function(){fetch('//evil')});" : text(/jsx-runtime\/(.+)\.js$/.exec(url)![1]!), { status: 200 })) as unknown as typeof fetch;
    await expect(loadJsxModules(manifest, source, { fetch: tampered, allowRunnerModules: true })).rejects.toThrow(/tinycloud-app refused/);
  });

  it("renderJsxPage sends the client module only to the page that registered a capability handler", async () => {
    for (const withHandler of [false, true]) {
      document.body.replaceChildren();
      const root = document.createElement("main");
      document.body.append(root);
      vi.stubGlobal("URL", Object.assign(URL, { createObjectURL: () => "blob:test", revokeObjectURL: () => undefined }));
      void renderJsxPage(root, source, { filename: "app.jsx", onCleanup: () => undefined, manifest, fetch: fetchImpl, ...(withHandler ? { onCapability: () => undefined } : {}) });
      const iframe = await vi.waitFor(() => { const found = root.querySelector("iframe"); if (found === null) throw new Error("wait"); return found; });
      const post = vi.spyOn(iframe.contentWindow!, "postMessage");
      window.dispatchEvent(new MessageEvent("message", { source: iframe.contentWindow, origin: "null", data: { v: 1, type: "bridge-ready", nonce: NONCE_OF(iframe) } }));
      const sent = post.mock.calls[0]![0] as { modules: Record<string, string>; source: string };
      expect(Object.keys(sent.modules).includes("tinycloud-app"), `handler: ${withHandler}`).toBe(withHandler);
      // The source goes in as bytes the person stored, verbatim.
      expect(sent.source).toBe(source);
      vi.unstubAllGlobals();
    }
  });
});

describe("the parent's reply to a capability request", () => {
  beforeEach(() => { document.body.replaceChildren(); });

  it("is {v,type:'cap/result',nonce,id,result}, posted to the sandbox's own frame only", () => {
    expect(Object.keys(buildCapabilityReply("n", "1", { ok: true })).sort()).toEqual(["id", "nonce", "result", "type", "v"]);
    const handler = vi.fn();
    const sandbox = createJsxSandbox(document, { onCapability: handler });
    const nonce = NONCE_OF(sandbox.iframe);
    const post = vi.spyOn(sandbox.iframe.contentWindow!, "postMessage");
    window.dispatchEvent(new MessageEvent("message", { source: sandbox.iframe.contentWindow, origin: "null", data: { v: 1, type: "cap/kv.get", nonce, body: { id: "7", args: { key: "a" } } } }));
    expect(handler).toHaveBeenCalledTimes(1);
    const reply = handler.mock.calls[0]![1] as (id: string, result: unknown) => void;
    reply("7", { ok: true });
    expect(post).toHaveBeenCalledExactlyOnceWith({ v: 1, type: "cap/result", nonce, id: "7", result: { ok: true } }, "*");
    sandbox.destroy();
    reply("7", { ok: true });
    expect(post).toHaveBeenCalledTimes(1);
  });

  it("a handler that throws does not break the message loop", () => {
    const sandbox = createJsxSandbox(document, { onCapability: () => { throw new Error("handler bug"); } });
    const nonce = NONCE_OF(sandbox.iframe);
    expect(() => window.dispatchEvent(new MessageEvent("message", { source: sandbox.iframe.contentWindow, origin: "null", data: { v: 1, type: "cap/kv.get", nonce, body: { id: "1", args: {} } } }))).not.toThrow();
    sandbox.destroy();
  });

  it("recognises only v:1, nonce-bound cap/* names with the keys {v,type,nonce,body}", () => {
    const nonce = "a".repeat(32);
    expect(parseCapabilityMessage({ v: 1, type: "cap/sql.query", nonce, body: { id: "1" } }, nonce)).toEqual({ type: "cap/sql.query", body: { id: "1" } });
    for (const data of [{ v: 1, type: "cap/sql.query", nonce: "b".repeat(32) }, { v: 2, type: "cap/sql.query", nonce }, { v: 1, type: "cap/SQL", nonce }, { v: 1, type: "cap/", nonce }, { v: 1, type: "kv.get", nonce }, { v: 1, type: "cap/kv.get", nonce, id: "1" }, [], null, "cap/kv.get"]) {
      expect(parseCapabilityMessage(data, nonce)).toBeUndefined();
    }
  });
});

describe("the in-frame client (@tinycloud/app)", () => {
  let posted: Array<Record<string, unknown>>;
  beforeEach(() => {
    posted = [];
    vi.useFakeTimers();
    vi.spyOn(window.parent, "postMessage").mockImplementation(((message: Record<string, unknown>, target: string) => {
      expect(target).toBe("*");
      posted.push(message);
    }) as typeof window.postMessage);
  });
  afterEach(() => { vi.useRealTimers(); vi.restoreAllMocks(); });

  const answer = (id: string, result: unknown, source: MessageEventSource | null = window.parent, extra: Record<string, unknown> = {}): void => {
    window.dispatchEvent(new MessageEvent("message", { source, data: { v: 1, type: "cap/result", id, result, ...extra } }));
  };

  it("posts one {v,type,id,args} message per call, to the parent, and resolves with the parent's answer", async () => {
    const pending = [
      kv.get("prefs/goals.json"),
      kv.put("prefs/goals.json", "x", { contentType: "text/plain", ifNoneMatch: true }),
      kv.put("prefs/photo", new Uint8Array([1])),
      kv.list(),
      kv.list("knowledge/"),
      kv.del("prefs/a"),
      sql.query("healthlog", "SELECT ?", [1]),
      sql.execute("healthlog", "DELETE FROM meal"),
    ];
    expect(posted.map((message) => [message["type"], message["args"]])).toEqual([
      ["cap/kv.get", { key: "prefs/goals.json" }],
      ["cap/kv.put", { key: "prefs/goals.json", body: "x", contentType: "text/plain", ifNoneMatch: true }],
      ["cap/kv.put", { key: "prefs/photo", body: new Uint8Array([1]) }],
      ["cap/kv.list", { key: "" }],
      ["cap/kv.list", { key: "knowledge/" }],
      ["cap/kv.del", { key: "prefs/a" }],
      ["cap/sql.query", { db: "healthlog", sql: "SELECT ?", params: [1] }],
      ["cap/sql.execute", { db: "healthlog", sql: "DELETE FROM meal", params: [] }],
    ]);
    expect(posted.every((message) => message["v"] === 1 && Object.keys(message).sort().join() === "args,id,type,v")).toBe(true);
    expect(posted.map((message) => message["type"])).toEqual(posted.map((message) => `cap/${CAP_OPS[CAP_TYPES.indexOf(message["type"] as string)]}`));
    // Answer out of order: each promise gets its own.
    for (const message of [...posted].reverse()) answer(message["id"] as string, { ok: true, echo: message["type"] });
    const results = await Promise.all(pending);
    expect(results.map((result) => (result as { echo?: string }).echo)).toEqual(posted.map((message) => message["type"]));
  });

  it("uses distinct ids that the bridge's id pattern accepts", () => {
    void kv.get("a");
    void kv.get("a");
    const ids = posted.map((message) => message["id"] as string);
    expect(new Set(ids).size).toBe(2);
    for (const id of ids) expect(id).toMatch(/^[0-9]{1,9}$/);
  });

  it("answers BAD_REQUEST by itself for arguments of the wrong type, sending nothing", async () => {
    const results: CapResult[] = await Promise.all([
      kv.get(1), kv.get(undefined), kv.put("a", 5), kv.put("a", { x: 1 }), kv.put("a", "x", { nope: 1 }), kv.put("a", "x", { ifNoneMatch: false }), kv.put("a", "x", "text"), kv.put("a", "x", []),
      kv.list(5), kv.del(null), sql.query(1, "x"), sql.query("d", 1), sql.query("d", "x", "p"), sql.execute("d", "x", {}),
    ]);
    expect(posted).toEqual([]);
    for (const result of results) expect(result).toMatchObject({ ok: false, error: { code: "BAD_REQUEST" } });
  });

  it("never throws or rejects: a value the browser cannot send is BAD_REQUEST, a hostile options object is contained", async () => {
    vi.mocked(window.parent.postMessage).mockImplementationOnce(() => { throw new DOMException("could not be cloned", "DataCloneError"); });
    expect(await sql.query("d", "SELECT ?", [() => 1])).toMatchObject({ ok: false, error: { code: "BAD_REQUEST" } });
    const hostile = new Proxy({}, { ownKeys: () => { throw new Error("trap"); } });
    expect(await kv.put("a", "x", hostile)).toMatchObject({ ok: false, error: { code: "BAD_REQUEST" } });
    const circular: unknown[] = [];
    circular.push(circular);
    vi.mocked(window.parent.postMessage).mockImplementationOnce(() => { throw new DOMException("cycle", "DataCloneError"); });
    expect(await sql.query("d", "SELECT ?", circular)).toMatchObject({ ok: false });
  });

  it("ignores answers that did not come from the parent, with the wrong shape, or for an unknown id", async () => {
    const pending = kv.get("a");
    const id = posted[0]!["id"] as string;
    answer(id, { ok: true }, null);
    answer(id, { ok: true }, {} as MessageEventSource);
    answer("999", { ok: true });
    answer(id, { ok: true }, window.parent, { v: 2 });
    answer(id, { ok: true }, window.parent, { type: "cap/kv.get" });
    let settled = false;
    void pending.then(() => { settled = true; });
    await vi.advanceTimersByTimeAsync(0);
    expect(settled).toBe(false);
    answer(id, "not a result");
    expect(await pending).toMatchObject({ ok: false, error: { code: "INTERNAL" } });
  });

  it("stops waiting a little after the parent would, saying the call may have been applied", async () => {
    const pending = kv.put("a", "x");
    await vi.advanceTimersByTimeAsync(CAP_LIMITS.clientWaitMs);
    const result = await pending;
    expect(result).toMatchObject({ ok: false, error: { code: "TIMEOUT" } });
    expect(result.ok ? "" : result.error.message).toMatch(/may still have been applied/);
    // A late answer changes nothing and throws nothing.
    expect(() => answer(posted[0]!["id"] as string, { ok: true })).not.toThrow();
  });

  it("is frozen: an app cannot replace the verbs another part of the app imported", () => {
    expect(Object.isFrozen(kv)).toBe(true);
    expect(Object.isFrozen(sql)).toBe(true);
    expect(() => { (kv as unknown as Record<string, unknown>)["get"] = () => null; }).toThrow();
  });
});

describe("no secret material in anything the frame sees or says", () => {
  const FORBIDDEN = /tc1[A-Za-z0-9]|privateKey|private_key|\bjwk\b|delegation|sessionKey|siwe|did:pkh|did:key|openkey|authorization|bearer/i;

  it("the client module and the bridge's relay code hold no key, token, DID or session vocabulary", () => {
    const client = readFileSync("src/artifact/jsx-runtime/app-module.ts", "utf8");
    // The comment at the top names the contract in words; code lines must not.
    const code = client.split("\n").filter((line) => !/^\s*(\/\/|\*|\/\*)/.test(line)).join("\n");
    expect(code).not.toMatch(FORBIDDEN);
    const relay = JSX_BRIDGE_RUNTIME_SCRIPT.slice(JSX_BRIDGE_RUNTIME_SCRIPT.indexOf("// ---- cap/*"), JSX_BRIDGE_RUNTIME_SCRIPT.indexOf("function fromChild"));
    expect(relay.length).toBeGreaterThan(500);
    expect(relay).not.toMatch(FORBIDDEN);
  });

  it("the request and reply envelopes have a fixed key set and nothing else", () => {
    expect(Object.keys(buildCapabilityReply("n", "1", { ok: true })).sort()).toEqual(["id", "nonce", "result", "type", "v"]);
  });
});
