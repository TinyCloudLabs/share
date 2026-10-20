import { createHash, webcrypto } from "node:crypto";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { JsxManifest } from "../src/artifact/jsx-runtime/files.js";
import { classifyContent, renderSafeContent } from "../src/viewer/content.js";
import {
  JSX_BRIDGE_RUNTIME_SCRIPT,
  JSX_SANDBOX_CSP,
  JSX_SANDBOX_HTTP_CSP,
  JSX_SANDBOX_HTTP_HEADERS,
  JSX_SANDBOX_PATH,
  buildJsxSandboxHtml,
  buildRenderRequest,
  parseFrameMessage,
} from "../src/viewer/jsx-frame.js";
import { JsxModuleIntegrityError, loadJsxModules, requiredFileIds, scanImportSpecifiers } from "../src/viewer/jsx-modules.js";
import { JsxRenderError, createJsxSandbox } from "../src/viewer/jsx-sandbox.js";
import { renderJsxPage } from "../src/viewer/jsx-render.js";

Object.defineProperty(globalThis, "crypto", { value: webcrypto, configurable: true });

const NONCE = "0123456789abcdef0123456789abcdef";

function stubObjectUrls(): void {
  vi.stubGlobal("URL", Object.assign(URL, { createObjectURL: () => "blob:test", revokeObjectURL: () => undefined }));
}

describe("JSX sandbox frame policy", () => {
  it("meta and header policies are the same string (the header adds only frame-ancestors) and refuse every remote load", () => {
    expect(buildJsxSandboxHtml("")).toContain(`<meta http-equiv="Content-Security-Policy" content="${JSX_SANDBOX_CSP}">`);
    expect(JSX_SANDBOX_HTTP_CSP).toBe(`${JSX_SANDBOX_CSP}; frame-ancestors 'self'`);
    expect(JSX_SANDBOX_HTTP_HEADERS).toContainEqual(["content-security-policy", JSX_SANDBOX_HTTP_CSP]);
    expect(JSX_SANDBOX_HTTP_HEADERS).toContainEqual(["x-frame-options", "SAMEORIGIN"]);
    expect(JSX_SANDBOX_CSP).toBe([
      "default-src 'none'",
      "script-src 'unsafe-inline' 'unsafe-eval'",
      "style-src 'unsafe-inline'",
      "img-src data: blob:",
      "font-src data: blob:",
      "media-src data: blob:",
      "connect-src 'none'",
      "frame-src 'none'",
      "worker-src 'none'",
      "object-src 'none'",
      "base-uri 'none'",
      "form-action 'none'",
    ].join("; "));
    // No directive may name a host or scheme that can load remote content.
    expect(JSX_SANDBOX_HTTP_CSP).not.toMatch(/https?:|\*|'self'(?!;|$)/);
  });

  it("serves the same complete policy from public/_headers on both routes, detaching the site-wide one", () => {
    const headers = readFileSync("public/_headers", "utf8");
    for (const route of ["/jsx-sandbox", JSX_SANDBOX_PATH]) {
      expect(headers).toContain(`\n${route}\n  ! Content-Security-Policy\n  Content-Security-Policy: ${JSX_SANDBOX_HTTP_CSP}\n  X-Frame-Options: SAMEORIGIN\n`);
    }
  });

  it("never mentions allow-same-origin or other sandbox escapes in source", () => {
    const files: string[] = [];
    const walk = (dir: string): void => {
      for (const entry of readdirSync(dir)) {
        const path = join(dir, entry);
        if (statSync(path).isDirectory()) walk(path);
        else if (/\.(ts|mjs|html|css)$/.test(entry)) files.push(path);
      }
    };
    walk("src");
    for (const path of files) {
      const text = readFileSync(path, "utf8");
      // Comments may name the forbidden tokens; only attribute assignments count.
      expect(text, path).not.toMatch(/setAttribute\(\s*["']sandbox["']\s*,\s*["'][^"']*allow-(same-origin|popups|top-navigation|forms|modals|downloads)/);
      expect(text, path).not.toMatch(/sandbox\s*=\s*["'][^"']*allow-(same-origin|popups|top-navigation|forms|modals|downloads)/);
    }
    const bridge = buildJsxSandboxHtml("");
    expect(bridge).not.toContain("allow-same-origin");
    expect(JSX_BRIDGE_RUNTIME_SCRIPT).not.toContain("allow-same-origin");
  });

  it("keeps the frame document free of any remote reference", () => {
    const html = buildJsxSandboxHtml(readFileSync("node_modules/@tinycloud/styles/src/tokens.css", "utf8"));
    expect(html).not.toMatch(/(?:src|href)\s*=\s*["']?(?:https?:)?\/\//i);
    expect(html).not.toMatch(/@import|url\(\s*["']?https?:/i);
  });

  it("escapes the artifact into the child document so it cannot break out of its script", () => {
    expect(buildJsxSandboxHtml("a{}")).not.toMatch(/<\/script>\s*<script>\s*alert/);
  });
});

describe("render message contract", () => {
  it("has exactly the keys {v,type,nonce,kind,source,modules,theme}", () => {
    const request = buildRenderRequest(NONCE, "export default () => null", { runtime: "x" }, "system");
    expect(Object.keys(request).sort()).toEqual(["kind", "modules", "nonce", "source", "theme", "type", "v"]);
    expect(request).toMatchObject({ v: 1, type: "render", kind: "jsx", theme: "system" });
  });

  it.each([
    ["wrong nonce", { v: 1, type: "ready", nonce: "f".repeat(32) }],
    ["wrong version", { v: 2, type: "ready", nonce: NONCE }],
    ["no version", { type: "ready", nonce: NONCE }],
    ["unknown type", { v: 1, type: "render", nonce: NONCE }],
    ["reserved capability namespace", { v: 1, type: "cap/storage.get", nonce: NONCE }],
    ["extra keys on ready", { v: 1, type: "ready", nonce: NONCE, extra: 1 }],
    ["bad error phase", { v: 1, type: "error", nonce: NONCE, phase: "network", message: "x" }],
    ["error without message", { v: 1, type: "error", nonce: NONCE, phase: "runtime" }],
    ["array", [{ v: 1, type: "ready", nonce: NONCE }]],
    ["null", null],
    ["string", "ready"],
  ])("rejects %s", (_label, data) => {
    expect(parseFrameMessage(data, NONCE)).toBeUndefined();
  });

  it("accepts the four allowed messages and truncates error text", () => {
    expect(parseFrameMessage({ v: 1, type: "bridge-ready", nonce: NONCE }, NONCE)).toEqual({ type: "bridge-ready" });
    expect(parseFrameMessage({ v: 1, type: "ready", nonce: NONCE }, NONCE)).toEqual({ type: "ready" });
    expect(parseFrameMessage({ v: 1, type: "restore-controls", nonce: NONCE }, NONCE)).toEqual({ type: "restore-controls" });
    const error = parseFrameMessage({ v: 1, type: "error", nonce: NONCE, phase: "compile", message: "x".repeat(5000), line: 7, module: "m".repeat(500) }, NONCE);
    expect(error).toMatchObject({ type: "error", phase: "compile", line: 7 });
    expect(error?.type === "error" && error.message.length).toBe(2048);
    expect(error?.type === "error" && error.module?.length).toBe(200);
    expect(parseFrameMessage({ v: 1, type: "error", nonce: NONCE, phase: "compile", message: "m", line: -3 }, NONCE)).toEqual({ type: "error", phase: "compile", message: "m" });
  });
});

describe("parent sandbox controller", () => {
  beforeEach(() => { document.body.replaceChildren(); });
  afterEach(() => { vi.useRealTimers(); vi.restoreAllMocks(); });

  function frameMessage(sandbox: ReturnType<typeof createJsxSandbox>, data: unknown, overrides: { source?: MessageEventSource | null; origin?: string } = {}): void {
    window.dispatchEvent(new MessageEvent("message", {
      source: overrides.source === undefined ? sandbox.iframe.contentWindow : overrides.source,
      origin: overrides.origin ?? "null",
      data,
    }));
  }
  const nonceOf = (sandbox: ReturnType<typeof createJsxSandbox>): string => new URL(sandbox.iframe.src).hash.slice(1);

  it("embeds the bridge with only allow-scripts, no permissions, no referrer and a 128-bit nonce", () => {
    const sandbox = createJsxSandbox(document);
    const { iframe } = sandbox;
    expect(iframe.getAttribute("sandbox")).toBe("allow-scripts");
    expect(iframe.getAttribute("allow")).toBe("");
    expect(iframe.getAttribute("referrerpolicy")).toBe("no-referrer");
    expect(new URL(iframe.src).pathname).toBe(JSX_SANDBOX_PATH);
    expect(nonceOf(sandbox)).toMatch(/^[0-9a-f]{32}$/);
    sandbox.destroy();
  });

  it("sends the render message only after the bridge is ready, and only that message", async () => {
    const sandbox = createJsxSandbox(document);
    const post = vi.spyOn(sandbox.iframe.contentWindow!, "postMessage");
    const rendered = sandbox.render("export default () => null", { runtime: "r" });
    expect(post).not.toHaveBeenCalled();
    frameMessage(sandbox, { v: 1, type: "bridge-ready", nonce: nonceOf(sandbox) });
    expect(post).toHaveBeenCalledTimes(1);
    const [payload, target] = post.mock.calls[0]!;
    expect(target).toBe("*");
    expect(Object.keys(payload as object).sort()).toEqual(["kind", "modules", "nonce", "source", "theme", "type", "v"]);
    frameMessage(sandbox, { v: 1, type: "ready", nonce: nonceOf(sandbox) });
    await expect(rendered).resolves.toBeUndefined();
    sandbox.destroy();
  });

  it("ignores messages from another source, a non-null origin, a wrong nonce or the wrong version", async () => {
    const sandbox = createJsxSandbox(document);
    const rendered = sandbox.render("x", { runtime: "r" });
    const settled = vi.fn();
    void rendered.then(settled, settled);
    const nonce = nonceOf(sandbox);
    frameMessage(sandbox, { v: 1, type: "ready", nonce }, { source: window });
    frameMessage(sandbox, { v: 1, type: "ready", nonce }, { source: null });
    frameMessage(sandbox, { v: 1, type: "ready", nonce }, { origin: "https://share.tinycloud.xyz" });
    frameMessage(sandbox, { v: 1, type: "ready", nonce: "0".repeat(32) });
    frameMessage(sandbox, { v: 2, type: "ready", nonce });
    frameMessage(sandbox, { type: "ready", nonce });
    await Promise.resolve();
    expect(settled).not.toHaveBeenCalled();
    frameMessage(sandbox, { v: 1, type: "ready", nonce });
    await expect(rendered).resolves.toBeUndefined();
    sandbox.destroy();
  });

  it("turns a frame error into a typed rejection and a later error into onFailure", async () => {
    const onFailure = vi.fn();
    const sandbox = createJsxSandbox(document, { onFailure });
    const rendered = sandbox.render("x", { runtime: "r" });
    const nonce = nonceOf(sandbox);
    frameMessage(sandbox, { v: 1, type: "error", nonce, phase: "compile", message: "Unexpected token", line: 4 });
    await expect(rendered).rejects.toMatchObject({ name: "JsxRenderError", phase: "compile", line: 4, message: "Unexpected token" });
    expect(onFailure).not.toHaveBeenCalled();
    sandbox.destroy();

    const second = createJsxSandbox(document, { onFailure });
    const ok = second.render("x", { runtime: "r" });
    frameMessage(second, { v: 1, type: "ready", nonce: nonceOf(second) });
    await ok;
    frameMessage(second, { v: 1, type: "error", nonce: nonceOf(second), phase: "runtime", message: "later" });
    expect(onFailure).toHaveBeenCalledWith(expect.objectContaining({ phase: "runtime", message: "later" }));
    second.destroy();
  });

  it("forwards the recall shortcut only from its own frame", () => {
    const onRestoreControls = vi.fn();
    const sandbox = createJsxSandbox(document, { onRestoreControls });
    frameMessage(sandbox, { v: 1, type: "restore-controls", nonce: nonceOf(sandbox) }, { source: window });
    expect(onRestoreControls).not.toHaveBeenCalled();
    frameMessage(sandbox, { v: 1, type: "restore-controls", nonce: nonceOf(sandbox) });
    expect(onRestoreControls).toHaveBeenCalledTimes(1);
    sandbox.destroy();
  });

  it("reports a start failure when no ready arrives in time", async () => {
    vi.useFakeTimers();
    const sandbox = createJsxSandbox(document);
    const rendered = sandbox.render("x", { runtime: "r" });
    const outcome = rendered.catch((error: unknown) => error);
    await vi.advanceTimersByTimeAsync(15_001);
    await expect(outcome).resolves.toMatchObject({ phase: "start" });
    sandbox.destroy();
  });

  it("refuses an oversize source before anything is sent", async () => {
    const sandbox = createJsxSandbox(document);
    await expect(sandbox.render("x".repeat(1024 * 1024 + 1), { runtime: "r" })).rejects.toBeInstanceOf(JsxRenderError);
    sandbox.destroy();
  });

  it("renders once per frame and rejects after destroy", async () => {
    const sandbox = createJsxSandbox(document);
    void sandbox.render("x", { runtime: "r" }).catch(() => undefined);
    await expect(sandbox.render("y", { runtime: "r" })).rejects.toThrow(/once/);
    sandbox.destroy();
    await expect(sandbox.render("y", { runtime: "r" })).rejects.toThrow(/destroyed/);
    expect(document.querySelector("iframe")).toBeNull();
  });
});

describe("import scan and verified module loading", () => {
  it("finds specifiers by string scan only, in every import form", () => {
    const source = [
      'import React, { useState } from "react";',
      "import * as d3 from 'd3';",
      'import "side-effect";',
      'export { a } from "re-export";',
      'export * from "star";',
      'const m = require("cjs");',
      'const lazy = await import("lazy");',
      'import {\n  A,\n  B,\n} from "multi\\u006cine";',
      '// import fake from "in-a-comment-is-still-listed-and-harmless";',
    ].join("\n");
    expect(scanImportSpecifiers(source)).toEqual(expect.arrayContaining(["react", "d3", "side-effect", "re-export", "star", "cjs", "lazy"]));
    expect(scanImportSpecifiers("const x = 1;")).toEqual([]);
  });

  it("stays linear on hostile input", () => {
    const hostile = `import ${"a, ".repeat(200_000)}`;
    const started = performance.now();
    scanImportSpecifiers(hostile);
    expect(performance.now() - started).toBeLessThan(2_000);
  });

  const text = (id: string): string => `__TC_DEFINE__(["${id}"],function(){});`;
  const digest = (value: string): string => createHash("sha256").update(value, "utf8").digest("hex");
  function manifestOf(overrides: Partial<Record<string, string>> = {}): { manifest: JsxManifest; fetchImpl: typeof fetch; requested: string[] } {
    const ids: Array<[string, readonly string[]]> = [["react", ["react", "react/jsx-runtime"]], ["react-dom", ["react-dom", "react-dom/client"]], ["runtime", ["@tc/runtime"]], ["tailwind", ["@tailwindcss/browser"]], ["lucide-react", ["lucide-react"]], ["recharts", ["recharts"]]];
    const files = Object.fromEntries(ids.map(([id, provides]) => [id, { id, url: `/assets/jsx-runtime/${id}.test.js`, sha256: digest(text(id)), bytes: Buffer.byteLength(text(id)), provides }]));
    const requested: string[] = [];
    const fetchImpl = (async (url: string) => {
      requested.push(url);
      const id = /jsx-runtime\/(.+)\.test\.js$/.exec(url)![1]!;
      const body = overrides[id] ?? text(id);
      return new Response(body, { status: 200 });
    }) as unknown as typeof fetch;
    return { manifest: { version: 1, files }, fetchImpl, requested };
  }

  it("sends the always-present files plus only the libraries a source imports", async () => {
    const { manifest, fetchImpl, requested } = manifestOf();
    expect(requiredFileIds(manifest, ["lucide-react", "unknown"]).sort()).toEqual(["lucide-react", "react", "react-dom", "runtime", "tailwind"]);
    const modules = await loadJsxModules(manifest, 'import { Cloud } from "lucide-react"; import x from "unknown-lib";', { fetch: fetchImpl });
    expect(Object.keys(modules).sort()).toEqual(["lucide-react", "react", "react-dom", "runtime", "tailwind"]);
    expect(requested.some((url) => url.includes("recharts"))).toBe(false);
    expect(requested.every((url) => url.startsWith("/assets/jsx-runtime/"))).toBe(true);
  });

  it("refuses a file whose sha256 differs from the manifest, and one whose size differs", async () => {
    const tampered = manifestOf({ runtime: text("runtime").replace("function", "functioN") });
    await expect(loadJsxModules(tampered.manifest, "export default () => null", { fetch: tampered.fetchImpl })).rejects.toThrow(JsxModuleIntegrityError);
    const resized = manifestOf({ react: `${text("react")} ` });
    await expect(loadJsxModules(resized.manifest, "x", { fetch: resized.fetchImpl })).rejects.toThrow(/size differs/);
  });

  it("refuses a manifest entry that points outside the runtime asset directory", async () => {
    const { manifest, fetchImpl } = manifestOf();
    const evil: JsxManifest = { version: 1, files: { ...manifest.files, runtime: { ...manifest.files["runtime"]!, url: "https://cdn.example/runtime.js" } } };
    await expect(loadJsxModules(evil, "x", { fetch: fetchImpl })).rejects.toThrow(/unexpected location/);
    const traversal: JsxManifest = { version: 1, files: { ...manifest.files, runtime: { ...manifest.files["runtime"]!, url: "/assets/jsx-runtime/../../viewer" } } };
    await expect(loadJsxModules(traversal, "x", { fetch: fetchImpl })).rejects.toThrow(/unexpected location/);
  });

  it("refuses non-ok responses", async () => {
    const { manifest } = manifestOf();
    const notFound = (async () => new Response("no", { status: 404 })) as unknown as typeof fetch;
    await expect(loadJsxModules(manifest, "x", { fetch: notFound })).rejects.toThrow(/HTTP 404/);
  });
});

describe("viewer integration", () => {
  beforeEach(() => { document.body.replaceChildren(); stubObjectUrls(); });
  afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks(); });

  const SOURCE = 'import { Cloud } from "lucide-react";\nexport default function App() { return <Cloud />; }\n';

  it("classifies JSX by signed type or unsigned bearer key extension", () => {
    expect(classifyContent({ mediaType: "text/jsx", filename: "a.txt", byteLength: 1 })).toBe("jsx");
    expect(classifyContent({ mediaType: "text/tsx;charset=utf-8", filename: "a.txt", byteLength: 1 })).toBe("jsx");
    expect(classifyContent({ mediaType: "application/octet-stream", filename: "App.JSX", byteLength: 1 })).toBe("jsx");
    expect(classifyContent({ mediaType: "application/octet-stream", filename: "App.tsx", byteLength: 1 })).toBe("jsx");
    // A signed non-JSX media type wins over a misleading extension, as for HTML.
    expect(classifyContent({ mediaType: "text/plain", filename: "App.jsx", byteLength: 1 })).toBe("text");
    expect(classifyContent({ mediaType: "image/svg+xml", filename: "App.jsx", byteLength: 1 })).toBe("download");
  });

  it.each([
    ["an addressed link", "policy"],
    ["an unknown link type", undefined],
  ] as const)("never runs JSX from %s and offers the download", async (_label, linkAccess) => {
    const root = document.createElement("main");
    document.body.append(root);
    const kind = await renderSafeContent(root, new TextEncoder().encode(SOURCE), { mediaType: "text/jsx", filename: "app.jsx", byteLength: 1 }, linkAccess === undefined ? {} : { linkAccess });
    expect(kind).toBe("download");
    expect(root.querySelector("iframe")).toBeNull();
    expect(root.textContent).toContain("Preview isn't available for this link type yet.");
    expect(root.querySelector("a[download]")).not.toBeNull();
  });

  it("hands a bearer JSX file only {v,type,nonce,kind,source,modules,theme} and nothing from the share URL", async () => {
    // The viewer's own address still carries the key at this point in a test; it must never travel.
    window.history.replaceState(null, "", "/viewer#tc1=SECRET-CAPABILITY&session=S&delegation=D&privateKey=K");
    const bytes = new TextEncoder().encode(SOURCE);
    const text = (id: string): string => `__TC_DEFINE__(["${id}"],function(){});`;
    const sha = (value: string): string => createHash("sha256").update(value, "utf8").digest("hex");
    const ids: Array<[string, readonly string[]]> = [["react", ["react"]], ["react-dom", ["react-dom"]], ["runtime", ["@tc/runtime"]], ["tailwind", ["@tailwindcss/browser"]], ["lucide-react", ["lucide-react"]]];
    const manifest: JsxManifest = { version: 1, files: Object.fromEntries(ids.map(([id, provides]) => [id, { id, url: `/assets/jsx-runtime/${id}.js`, sha256: sha(text(id)), bytes: text(id).length, provides }])) };
    const fetchImpl = (async (url: string) => new Response(text(/jsx-runtime\/(.+)\.js$/.exec(url)![1]!), { status: 200 })) as unknown as typeof fetch;
    const root = document.createElement("main");
    document.body.append(root);
    const cleanups: Array<() => void> = [];
    const done = renderJsxPage(root, SOURCE, { filename: "app.jsx", bytes, onCleanup: (cleanup) => cleanups.push(cleanup), manifest, fetch: fetchImpl });
    const iframe = await vi.waitFor(() => { const found = root.querySelector("iframe"); if (found === null) throw new Error("no frame yet"); return found; });
    expect(iframe.getAttribute("sandbox")).toBe("allow-scripts");
    const post = vi.spyOn(iframe.contentWindow!, "postMessage");
    const nonce = new URL(iframe.src).hash.slice(1);
    window.dispatchEvent(new MessageEvent("message", { source: iframe.contentWindow, origin: "null", data: { v: 1, type: "bridge-ready", nonce } }));
    expect(post).toHaveBeenCalledTimes(1);
    const payload = post.mock.calls[0]![0] as Record<string, unknown>;
    expect(Object.keys(payload).sort()).toEqual(["kind", "modules", "nonce", "source", "theme", "type", "v"]);
    expect(payload["source"]).toBe(SOURCE);
    const serialized = JSON.stringify(payload);
    for (const secret of ["tc1=", "SECRET-CAPABILITY", "session", "delegation", "privateKey", "viewer#", location.href]) expect(serialized).not.toContain(secret);
    window.dispatchEvent(new MessageEvent("message", { source: iframe.contentWindow, origin: "null", data: { v: 1, type: "ready", nonce } }));
    await done;
    cleanups.forEach((cleanup) => cleanup());
  });

  it("shows a panel (and never a frame) when a library file fails its digest, using textContent only", async () => {
    const manifest: JsxManifest = {
      version: 1,
      files: Object.fromEntries(["react", "react-dom", "runtime", "tailwind"].map((id) => [id, { id, url: `/assets/jsx-runtime/${id}.js`, sha256: "0".repeat(64), bytes: 1, provides: [id] }])),
    };
    const fetchImpl = (async () => new Response("x", { status: 200 })) as unknown as typeof fetch;
    const root = document.createElement("main");
    document.body.append(root);
    await renderJsxPage(root, "export default () => null", { filename: "app.jsx", bytes: new Uint8Array(), onCleanup: () => undefined, manifest, fetch: fetchImpl });
    expect(root.querySelector("iframe")).toBeNull();
    expect(root.querySelector(".viewer-jsx-panel")?.textContent).toContain("couldn't be verified");
  });

  it("shows frame error text as text, with the line, and the library list for an unknown import", async () => {
    const text = (id: string): string => `__TC_DEFINE__(["${id}"],function(){});`;
    const sha = (value: string): string => createHash("sha256").update(value, "utf8").digest("hex");
    const manifest: JsxManifest = { version: 1, files: Object.fromEntries(["react", "react-dom", "runtime", "tailwind"].map((id) => [id, { id, url: `/assets/jsx-runtime/${id}.js`, sha256: sha(text(id)), bytes: text(id).length, provides: [id] }])) };
    const fetchImpl = (async (url: string) => new Response(text(/jsx-runtime\/(.+)\.js$/.exec(url)![1]!), { status: 200 })) as unknown as typeof fetch;

    for (const [data, expected] of [
      [{ phase: "compile", message: "<img src=x onerror=alert(1)> Unexpected token", line: 9 }, ["Line 9", "<img src=x onerror=alert(1)>"]],
      [{ phase: "import", message: "Cannot find module", module: "canvas-confetti" }, ["canvas-confetti isn't available", "Available: react"]],
    ] as const) {
      document.body.replaceChildren();
      const root = document.createElement("main");
      document.body.append(root);
      const done = renderJsxPage(root, "x", { filename: "app.jsx", bytes: new Uint8Array([120]), onCleanup: () => undefined, manifest, fetch: fetchImpl });
      const iframe = await vi.waitFor(() => { const found = root.querySelector("iframe"); if (found === null) throw new Error("wait"); return found; });
      const nonce = new URL(iframe.src).hash.slice(1);
      window.dispatchEvent(new MessageEvent("message", { source: iframe.contentWindow, origin: "null", data: { v: 1, type: "error", nonce, ...data } }));
      await done;
      const panel = root.querySelector(".viewer-jsx-panel")!;
      for (const piece of expected) expect(panel.textContent).toContain(piece);
      expect(panel.querySelector("img")).toBeNull();
      expect(root.querySelector("iframe")).toBeNull();
    }
  });
});

// The bridge script itself, run against a mock environment: the guards are
// proven by execution, not by matching the source text.
describe("bridge document script", () => {
  interface FakeChild {
    attrs: Record<string, string>;
    srcdoc: string;
    removed: boolean;
    listeners: Record<string, () => void>;
    contentWindow: object;
  }

  function startBridge(options: { origin?: string; hash?: string } = {}): {
    send(data: unknown, source?: "parent" | "child" | "other", origin?: string): void;
    posted: Array<Record<string, unknown>>;
    child(): FakeChild | null;
    fireChildLoad(): void;
    listening: boolean;
  } {
    const posted: Array<Record<string, unknown>> = [];
    let handler: ((event: { source: unknown; origin: string; data: unknown }) => void) | undefined;
    const parent = { postMessage: (message: Record<string, unknown>, target: string) => { expect(target).toBe("*"); posted.push(message); } };
    let child: FakeChild | null = null;
    const documentMock = {
      getElementById: () => ({ textContent: "/* frame css */" }),
      createElement: () => {
        const created: FakeChild = {
          attrs: {}, srcdoc: "", removed: false, listeners: {}, contentWindow: {},
        };
        return Object.assign(created, {
          setAttribute: (name: string, value: string) => { created.attrs[name] = value; },
          addEventListener: (type: string, listener: () => void) => { created.listeners[type] = listener; },
          remove: () => { created.removed = true; },
          className: "",
        });
      },
      body: { replaceChildren: (node: FakeChild) => { child = node; } },
    };
    const windowMock = {
      location: { hash: options.hash ?? `#${NONCE}` },
      parent,
      addEventListener: (type: string, listener: typeof handler) => { if (type === "message") handler = listener; },
    };
    new Function("window", "self", "document", JSX_BRIDGE_RUNTIME_SCRIPT)(windowMock, { origin: options.origin ?? "null" }, documentMock);
    return {
      posted,
      listening: handler !== undefined,
      child: () => child,
      fireChildLoad: () => child?.listeners["load"]?.(),
      send: (data, source = "parent", origin = "null") => {
        handler?.({ source: source === "parent" ? parent : source === "child" ? child?.contentWindow : {}, origin, data });
      },
    };
  }

  const render = (overrides: Record<string, unknown> = {}): Record<string, unknown> => ({
    v: 1, type: "render", nonce: NONCE, kind: "jsx", source: "export default () => null", modules: { runtime: "/*r*/" }, theme: "system", ...overrides,
  });

  it("refuses to initialise outside an opaque-origin sandbox or without a 128-bit nonce", () => {
    expect(startBridge({ origin: "https://share.tinycloud.xyz" }).listening).toBe(false);
    expect(startBridge({ hash: "#short" }).listening).toBe(false);
    expect(startBridge({ hash: "" }).listening).toBe(false);
    expect(startBridge({ hash: `#${"G".repeat(32)}` }).listening).toBe(false);
  });

  it("announces itself, then accepts one valid render from its parent only", () => {
    const bridge = startBridge();
    expect(bridge.posted).toEqual([{ v: 1, nonce: NONCE, type: "bridge-ready" }]);
    bridge.send(render(), "other");
    bridge.send(render(), "child");
    expect(bridge.child()).toBeNull();
    bridge.send(render());
    expect(bridge.child()).not.toBeNull();
    const child = bridge.child()!;
    expect(child.attrs["sandbox"]).toBe("allow-scripts");
    expect(child.attrs["allow"]).toBe("");
    expect(child.attrs["referrerpolicy"]).toBe("no-referrer");
    expect(child.srcdoc).toContain('data-theme="system"');
    expect(child.srcdoc).toContain("/* frame css */");
    expect(child.srcdoc).toContain("/*r*/");
    bridge.send(render({ source: "second" }));
    expect(bridge.child()).toBe(child);
  });

  it.each([
    ["wrong nonce", { nonce: "f".repeat(32) }],
    ["wrong version", { v: 2 }],
    ["wrong type", { type: "cap/read" }],
    ["wrong kind", { kind: "html" }],
    ["unknown theme", { theme: "neon" }],
    ["extra key", { extra: true }],
    ["source not a string", { source: 5 }],
    ["source too large", { source: "x".repeat(1024 * 1024 + 1) }],
    ["no runtime module", { modules: { react: "/*x*/" } }],
    ["modules not an object", { modules: ["runtime"] }],
    ["module name with a path", { modules: { runtime: "/*r*/", "../evil": "/*x*/" } }],
    ["module name proto-like", { modules: { runtime: "/*r*/", "Constructor": "/*x*/" } }],
    ["module text ending its script element", { modules: { runtime: "/*r*/ </script><script>bad()</script>" } }],
    ["module text opening a comment", { modules: { runtime: "/*r*/ <!-- x" } }],
    ["module text not a string", { modules: { runtime: 1 } }],
  ])("drops a render with %s without creating a frame or replying", (_label, override) => {
    const bridge = startBridge();
    bridge.send(render(override));
    expect(bridge.child()).toBeNull();
    expect(bridge.posted).toHaveLength(1);
  });

  it("drops a render missing a key", () => {
    const bridge = startBridge();
    const { theme: _theme, ...withoutTheme } = render();
    bridge.send(withoutTheme);
    expect(bridge.child()).toBeNull();
  });

  it("inlines source only as escaped JSON data, so it cannot end or add a script", () => {
    const bridge = startBridge();
    bridge.send(render({ source: 'export default () => "</script><script>stealthy()</script><!-- \u2028 & >"' }));
    const { srcdoc } = bridge.child()!;
    expect(srcdoc).not.toContain("stealthy()</script>");
    expect(srcdoc.match(/<\/script/gi)?.length).toBe(srcdoc.match(/<script/gi)?.length);
    const json = /<script type="application\/json" id="tc-input">([\s\S]*?)<\/script>/.exec(srcdoc)![1]!;
    expect(json).not.toMatch(/[<>&\u2028\u2029]/);
    expect(JSON.parse(json)).toEqual({ source: 'export default () => "</script><script>stealthy()</script><!-- \u2028 & >"', theme: "system" });
  });

  it("forwards child ready once, errors capped and sanitised, and drops everything else", () => {
    const bridge = startBridge();
    bridge.send(render());
    const before = bridge.posted.length;
    bridge.send({ v: 1, type: "ready" }, "other");
    bridge.send({ v: 1, type: "ready" }, "child", "https://share.tinycloud.xyz");
    bridge.send({ v: 2, type: "ready" }, "child");
    bridge.send({ v: 1, type: "cap/storage.get", key: "k" }, "child");
    bridge.send({ v: 1, type: "navigate", path: "/viewer" }, "child");
    expect(bridge.posted).toHaveLength(before);
    bridge.send({ v: 1, type: "ready", leaked: "x" }, "child");
    bridge.send({ v: 1, type: "ready" }, "child");
    expect(bridge.posted.slice(before)).toEqual([{ v: 1, nonce: NONCE, type: "ready" }]);
    bridge.send({ v: 1, type: "error", phase: "runtime", message: "m".repeat(5000), line: 3.5, module: 7, extra: "dropped" }, "child");
    const error = bridge.posted.at(-1)!;
    expect(Object.keys(error).sort()).toEqual(["message", "nonce", "phase", "type", "v"]);
    expect((error["message"] as string).length).toBe(2048);
    bridge.send({ v: 1, type: "error", phase: "network", message: "x" }, "child");
    expect(bridge.posted.at(-1)).toBe(error);
    bridge.send({ v: 1, type: "restore-controls" }, "child");
    expect(bridge.posted.at(-1)).toEqual({ v: 1, nonce: NONCE, type: "restore-controls" });
  });

  it("limits how many errors one frame may send", () => {
    const bridge = startBridge();
    bridge.send(render());
    for (let index = 0; index < 20; index++) bridge.send({ v: 1, type: "error", phase: "runtime", message: String(index) }, "child");
    expect(bridge.posted.filter((message) => message["type"] === "error")).toHaveLength(5);
  });

  it("closes the child and reports it when the child document navigates", () => {
    const bridge = startBridge();
    bridge.send(render());
    const child = bridge.child()!;
    bridge.fireChildLoad();
    expect(child.removed).toBe(false);
    bridge.fireChildLoad();
    expect(child.removed).toBe(true);
    expect(bridge.posted.at(-1)).toMatchObject({ type: "error", phase: "runtime", message: expect.stringContaining("another page") });
  });
});
