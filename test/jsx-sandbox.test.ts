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
import { SANDBOX_PERMISSIONS_POLICY } from "../src/viewer/sandbox-permissions.js";
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
    // No fullscreen or Picture-in-Picture over the viewer's chrome, for the bridge and its child.
    expect(SANDBOX_PERMISSIONS_POLICY).toContain("fullscreen=()");
    expect(SANDBOX_PERMISSIONS_POLICY).toContain("picture-in-picture=()");
    expect(JSX_SANDBOX_HTTP_HEADERS).toContainEqual(["permissions-policy", SANDBOX_PERMISSIONS_POLICY]);
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
      expect(headers).toContain(`\n${route}\n  ! Content-Security-Policy\n  Content-Security-Policy: ${JSX_SANDBOX_HTTP_CSP}\n  Permissions-Policy: ${SANDBOX_PERMISSIONS_POLICY}\n  X-Frame-Options: SAMEORIGIN\n`);
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
      // allow-popups is granted by the markdown preview frame on purpose; it is not listed here.
      expect(text, path).not.toMatch(/setAttribute\(\s*["']sandbox["']\s*,\s*["'][^"']*allow-(same-origin|top-navigation|forms|modals|downloads)/);
      expect(text, path).not.toMatch(/sandbox\s*=\s*["'][^"']*allow-(same-origin|top-navigation|forms|modals|downloads)/);
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

  it("passes the recall request on only from its own frame, after the page started, at most once a second", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2030-01-01T00:00:10Z"));
    const onRestoreControls = vi.fn();
    const sandbox = createJsxSandbox(document, { onRestoreControls });
    const nonce = nonceOf(sandbox);
    const restore = { v: 1, type: "restore-controls", nonce };
    frameMessage(sandbox, restore, { source: window });
    // Before the page started a frame has no business asking for the chrome.
    frameMessage(sandbox, restore);
    expect(onRestoreControls).not.toHaveBeenCalled();
    const rendered = sandbox.render("x", { runtime: "r" });
    frameMessage(sandbox, { v: 1, type: "ready", nonce });
    await rendered;
    frameMessage(sandbox, restore, { source: window });
    expect(onRestoreControls).not.toHaveBeenCalled();
    frameMessage(sandbox, restore);
    for (let burst = 0; burst < 20; burst += 1) frameMessage(sandbox, restore);
    expect(onRestoreControls).toHaveBeenCalledTimes(1);
    vi.setSystemTime(new Date("2030-01-01T00:00:11.100Z"));
    frameMessage(sandbox, restore);
    expect(onRestoreControls).toHaveBeenCalledTimes(2);
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

  it("renderJsxPage refuses an oversize source before scanning or fetching anything", async () => {
    stubObjectUrls();
    const fetchSpy = vi.fn();
    const root = document.createElement("main");
    document.body.append(root);
    await renderJsxPage(root, `import "x";\n${"a".repeat(512 * 1024)}`, { filename: "big.jsx", onCleanup: () => undefined, fetch: fetchSpy as unknown as typeof fetch, manifest: { version: 1, files: {} } });
    expect(fetchSpy).not.toHaveBeenCalled();
    expect(root.querySelector("iframe")).toBeNull();
    expect(root.querySelector(".viewer-jsx-panel")?.textContent).toContain("too large");
  });

  it("refuses an oversize source before anything is sent", async () => {
    const sandbox = createJsxSandbox(document);
    await expect(sandbox.render("x".repeat(512 * 1024 + 1), { runtime: "r" })).rejects.toBeInstanceOf(JsxRenderError);
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
    const done = renderJsxPage(root, bytes, { filename: "app.jsx", onCleanup: (cleanup) => cleanups.push(cleanup), manifest, fetch: fetchImpl });
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

  it("shows an honest \"updating\" panel (and never a frame) when a library file fails its digest or cannot be fetched", async () => {
    const manifest: JsxManifest = {
      version: 1,
      files: Object.fromEntries(["react", "react-dom", "runtime", "tailwind"].map((id) => [id, { id, url: `/assets/jsx-runtime/${id}.js`, sha256: "0".repeat(64), bytes: 1, provides: [id] }])),
    };
    const fetchImpl = (async () => new Response("x", { status: 200 })) as unknown as typeof fetch;
    const root = document.createElement("main");
    document.body.append(root);
    await renderJsxPage(root, "export default () => null", { filename: "app.jsx", onCleanup: () => undefined, manifest, fetch: fetchImpl });
    expect(root.querySelector("iframe")).toBeNull();
    expect(root.querySelector(".viewer-jsx-panel")?.textContent).toContain("This artifact viewer is updating");
    expect(root.querySelector(".viewer-jsx-panel")?.textContent).toContain("Try again in a minute");
  });

  it("shows frame error text as text, with the line, and the library list for an unknown import", async () => {
    const text = (id: string): string => `__TC_DEFINE__(["${id}"],function(){});`;
    const sha = (value: string): string => createHash("sha256").update(value, "utf8").digest("hex");
    const manifest: JsxManifest = { version: 1, files: Object.fromEntries(["react", "react-dom", "runtime", "tailwind"].map((id) => [id, { id, url: `/assets/jsx-runtime/${id}.js`, sha256: sha(text(id)), bytes: text(id).length, provides: [id] }])) };
    const fetchImpl = (async (url: string) => new Response(text(/jsx-runtime\/(.+)\.js$/.exec(url)![1]!), { status: 200 })) as unknown as typeof fetch;

    for (const [data, expected] of [
      [{ phase: "compile", message: "<img src=x onerror=alert(1)> Unexpected token", line: 9 }, ["Line 9", "<img src=x onerror=alert(1)>"]],
      [{ phase: "import", message: "Cannot find module", module: "canvas-confetti" }, ["needs a library that isn't available", "Import from the file: canvas-confetti", "Available: react"]],
    ] as const) {
      document.body.replaceChildren();
      const root = document.createElement("main");
      document.body.append(root);
      const done = renderJsxPage(root, "x", { filename: "app.jsx", onCleanup: () => undefined, manifest, fetch: fetchImpl });
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

describe("loading state and retry", () => {
  beforeEach(() => { document.body.replaceChildren(); stubObjectUrls(); });
  afterEach(() => { vi.useRealTimers(); vi.unstubAllGlobals(); vi.restoreAllMocks(); });

  const text = (id: string): string => `__TC_DEFINE__(["${id}"],function(){});`;
  const sha = (value: string): string => createHash("sha256").update(value, "utf8").digest("hex");
  const files = ["react", "react-dom", "runtime", "tailwind"];
  const manifest: JsxManifest = { version: 1, files: Object.fromEntries(files.map((id) => [id, { id, url: `/assets/jsx-runtime/${id}.js`, sha256: sha(text(id)), bytes: text(id).length, provides: [id] }])) };
  const okFetch = (async (url: string) => new Response(text(/jsx-runtime\/(.+)\.js$/.exec(url)![1]!), { status: 200 })) as unknown as typeof fetch;

  it("covers the area with a polite status from the first moment, and removes it when the page reports ready", async () => {
    let release!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    const slowFetch = (async (url: string) => { await gate; return okFetch(url); }) as unknown as typeof fetch;
    const root = document.createElement("main");
    document.body.append(root);
    const done = renderJsxPage(root, "export default () => null", { filename: "app.jsx", onCleanup: () => undefined, manifest, fetch: slowFetch });
    // Libraries still loading: no frame yet, but the cover is already there.
    const cover = root.querySelector<HTMLElement>(".viewer-jsx-loading")!;
    expect(cover.getAttribute("role")).toBe("status");
    expect(cover.textContent).toContain("Loading the page…");
    expect(root.querySelector("iframe")).toBeNull();
    release();
    const iframe = await vi.waitFor(() => { const found = root.querySelector("iframe"); if (found === null) throw new Error("wait"); return found; });
    expect(root.querySelector(".viewer-jsx-loading")).not.toBeNull();
    const nonce = new URL(iframe.src).hash.slice(1);
    window.dispatchEvent(new MessageEvent("message", { source: iframe.contentWindow, origin: "null", data: { v: 1, type: "bridge-ready", nonce } }));
    window.dispatchEvent(new MessageEvent("message", { source: iframe.contentWindow, origin: "null", data: { v: 1, type: "ready", nonce } }));
    await done;
    expect(root.querySelector(".viewer-jsx-loading")).toBeNull();
    expect(root.querySelector("iframe")).toBe(iframe);
  });

  it("says so after the slow threshold, keeps waiting, and Try again starts over", async () => {
    vi.useFakeTimers();
    const root = document.createElement("main");
    document.body.append(root);
    void renderJsxPage(root, "export default () => null", { filename: "app.jsx", onCleanup: () => undefined, manifest, fetch: okFetch, slowAfterMs: 5_000 });
    await vi.waitFor(() => { if (root.querySelector("iframe") === null) throw new Error("wait"); });
    await vi.advanceTimersByTimeAsync(4_000);
    expect(root.querySelector(".viewer-jsx-loading")!.getAttribute("data-state")).toBe("loading");
    await vi.advanceTimersByTimeAsync(1_500);
    const cover = root.querySelector<HTMLElement>(".viewer-jsx-loading")!;
    expect(cover.getAttribute("data-state")).toBe("slow");
    expect(cover.textContent).toContain("This page is taking a long time to start");
    const firstFrame = root.querySelector("iframe")!;
    cover.querySelector<HTMLButtonElement>("button")!.click();
    await vi.advanceTimersByTimeAsync(50);
    expect(firstFrame.isConnected).toBe(false);
    expect(root.querySelector("iframe")).not.toBe(firstFrame);
    expect(root.querySelector(".viewer-jsx-loading")!.getAttribute("data-state")).toBe("loading");
  });

  it("turns the sandbox's own start timeout into a recipient-facing panel with Try again and the source", async () => {
    vi.useFakeTimers();
    const root = document.createElement("main");
    document.body.append(root);
    void renderJsxPage(root, "export default () => null", { filename: "app.jsx", onCleanup: () => undefined, manifest, fetch: okFetch });
    // Digest checking is real async work; wait for the frame, then let the 15 s start timeout pass.
    await vi.waitFor(() => { if (root.querySelector("iframe") === null) throw new Error("wait"); });
    await vi.advanceTimersByTimeAsync(16_000);
    const panel = root.querySelector(".viewer-jsx-panel")!;
    expect(panel.textContent).toContain("This page is taking a long time to start");
    expect(panel.textContent).toContain("Try again");
    expect(panel.querySelector("a[download]")?.getAttribute("download")).toBe("app.jsx");
    expect(root.querySelector("iframe")).toBeNull();
    expect(root.querySelector(".viewer-jsx-loading")).toBeNull();
  });

  it("ends a render that is still loading when its container's content is replaced", async () => {
    let release!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    const slowFetch = (async (url: string) => { await gate; return okFetch(url); }) as unknown as typeof fetch;
    const root = document.createElement("main");
    document.body.append(root);
    const cleanups: Array<() => void> = [];
    const done = renderJsxPage(root, "export default () => null", { filename: "app.jsx", onCleanup: (cleanup) => cleanups.push(cleanup), manifest, fetch: slowFetch });
    cleanups.forEach((cleanup) => cleanup());
    release();
    await done;
    expect(document.querySelector("iframe")).toBeNull();
  });

  it("uses recipient-appropriate copy, never telling the reader to publish", async () => {
    const root = document.createElement("main");
    document.body.append(root);
    const done = renderJsxPage(root, "x", { filename: "app.jsx", onCleanup: () => undefined, manifest, fetch: okFetch });
    const iframe = await vi.waitFor(() => { const found = root.querySelector("iframe"); if (found === null) throw new Error("wait"); return found; });
    const nonce = new URL(iframe.src).hash.slice(1);
    window.dispatchEvent(new MessageEvent("message", { source: iframe.contentWindow, origin: "null", data: { v: 1, type: "error", nonce, phase: "compile", message: "Unexpected token", line: 2 } }));
    await done;
    const copy = root.querySelector(".viewer-jsx-panel")!.textContent!;
    expect(copy).toContain("Ask the sender to share it again");
    expect(copy).not.toMatch(/publish|Nothing was run/i);
  });
});

describe("extension points", () => {
  beforeEach(() => { document.body.replaceChildren(); stubObjectUrls(); });
  afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks(); });

  const send = (sandbox: ReturnType<typeof createJsxSandbox>, data: unknown, source: MessageEventSource | null = sandbox.iframe.contentWindow, origin = "null"): void => {
    window.dispatchEvent(new MessageEvent("message", { source, origin, data }));
  };
  const nonceOf = (sandbox: ReturnType<typeof createJsxSandbox>): string => new URL(sandbox.iframe.src).hash.slice(1);

  it("drops every cap/* message by default, and a registered handler sees only identity-valid ones", async () => {
    const onFailure = vi.fn();
    const onRestoreControls = vi.fn();
    const quiet = createJsxSandbox(document, { onFailure, onRestoreControls });
    const settled = vi.fn();
    void quiet.render("x", { runtime: "r" }).then(settled, settled);
    // Whatever they are named, cap/* messages trigger nothing: not a result, a failure or a reveal.
    for (const type of ["cap/kv.get", "cap/ready", "cap/error", "cap/restore-controls"]) {
      expect(() => send(quiet, { v: 1, type, nonce: nonceOf(quiet), body: { path: "a" } })).not.toThrow();
    }
    await Promise.resolve();
    expect(settled).not.toHaveBeenCalled();
    expect(onFailure).not.toHaveBeenCalled();
    expect(onRestoreControls).not.toHaveBeenCalled();
    quiet.destroy();

    const handler = vi.fn();
    const wired = createJsxSandbox(document, { onCapability: handler });
    const nonce = nonceOf(wired);
    send(wired, { v: 1, type: "cap/kv.get", nonce, body: { path: "a" } }, window);
    send(wired, { v: 1, type: "cap/kv.get", nonce }, wired.iframe.contentWindow, "https://share.tinycloud.xyz");
    send(wired, { v: 1, type: "cap/kv.get", nonce: "0".repeat(32) });
    send(wired, { v: 2, type: "cap/kv.get", nonce });
    send(wired, { v: 1, type: "cap/../escape", nonce });
    send(wired, { v: 1, type: "cap/kv.get", nonce, extra: 1 });
    expect(handler).not.toHaveBeenCalled();
    send(wired, { v: 1, type: "cap/kv.get", nonce, body: { path: "a" } });
    expect(handler).toHaveBeenCalledTimes(1);
    expect(handler.mock.calls[0]![0]).toEqual({ type: "cap/kv.get", body: { path: "a" } });
    expect(typeof handler.mock.calls[0]![1]).toBe("function");
    wired.destroy();
  });

  it("runs source bytes handed in directly, with its own title and theme, and no share descriptor", async () => {
    const source = "export default () => null;";
    const text = (id: string): string => `__TC_DEFINE__(["${id}"],function(){});`;
    const sha = (value: string): string => createHash("sha256").update(value, "utf8").digest("hex");
    const files = ["react", "react-dom", "runtime", "tailwind"];
    const manifest: JsxManifest = { version: 1, files: Object.fromEntries(files.map((id) => [id, { id, url: `/assets/jsx-runtime/${id}.js`, sha256: sha(text(id)), bytes: text(id).length, provides: [id] }])) };
    const fetchImpl = (async (url: string) => new Response(text(/jsx-runtime\/(.+)\.js$/.exec(url)![1]!), { status: 200 })) as unknown as typeof fetch;
    const root = document.createElement("main");
    document.body.append(root);
    const done = renderJsxPage(root, new TextEncoder().encode(source), { filename: "app.jsx", title: "Tiny app", theme: "dark", onCleanup: () => undefined, manifest, fetch: fetchImpl });
    const iframe = await vi.waitFor(() => { const found = root.querySelector("iframe"); if (found === null) throw new Error("wait"); return found; });
    expect(iframe.getAttribute("title")).toBe("Tiny app");
    const post = vi.spyOn(iframe.contentWindow!, "postMessage");
    const nonce = new URL(iframe.src).hash.slice(1);
    window.dispatchEvent(new MessageEvent("message", { source: iframe.contentWindow, origin: "null", data: { v: 1, type: "bridge-ready", nonce } }));
    expect(post.mock.calls[0]![0]).toMatchObject({ source, theme: "dark", kind: "jsx" });
    window.dispatchEvent(new MessageEvent("message", { source: iframe.contentWindow, origin: "null", data: { v: 1, type: "ready", nonce } }));
    await done;
    // Invalid UTF-8 never reaches the frame.
    document.body.replaceChildren();
    const other = document.createElement("main");
    document.body.append(other);
    await renderJsxPage(other, Uint8Array.from([0xff, 0xfe, 0xfd]), { filename: "bad.jsx", onCleanup: () => undefined, manifest, fetch: fetchImpl });
    expect(other.querySelector("iframe")).toBeNull();
    expect(other.querySelector(".viewer-jsx-panel")?.textContent).toContain("isn't text");
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
    replaced: unknown[][];
    child(): FakeChild | null;
    fireChildLoad(): void;
    listening: boolean;
    /** What the bridge posted into its child frame. */
    childPosted: Array<Record<string, unknown>>;
  } {
    const childPosted: Array<Record<string, unknown>> = [];
    const posted: Array<Record<string, unknown>> = [];
    const replaced: unknown[][] = [];
    let handler: ((event: { source: unknown; origin: string; data: unknown }) => void) | undefined;
    const parent = { postMessage: (message: Record<string, unknown>, target: string) => { expect(target).toBe("*"); posted.push(message); } };
    let child: FakeChild | null = null;
    const documentMock = {
      getElementById: () => ({ textContent: "/* frame css */" }),
      createElement: () => {
        const created: FakeChild = {
          attrs: {}, srcdoc: "", removed: false, listeners: {}, contentWindow: { postMessage: (message: Record<string, unknown>, target: string) => { expect(target).toBe("*"); childPosted.push(message); } },
        };
        return Object.assign(created, {
          setAttribute: (name: string, value: string) => { created.attrs[name] = value; },
          addEventListener: (type: string, listener: () => void) => { created.listeners[type] = listener; },
          remove: () => { created.removed = true; if (child === created) child = null; },
          className: "",
        });
      },
      body: { replaceChildren: (node: FakeChild) => { child = node; } },
    };
    const windowMock = {
      location: { hash: options.hash ?? `#${NONCE}`, pathname: "/jsx-sandbox.html", search: "" },
      history: { replaceState: (...args: unknown[]) => { replaced.push(args); } },
      parent,
      addEventListener: (type: string, listener: typeof handler) => { if (type === "message") handler = listener; },
    };
    new Function("window", "self", "document", JSX_BRIDGE_RUNTIME_SCRIPT)(windowMock, { origin: options.origin ?? "null" }, documentMock);
    return {
      posted,
      replaced,
      childPosted,
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

  it("drops the nonce from its own URL before the child can read it through baseURI", () => {
    const bridge = startBridge();
    expect(bridge.replaced).toEqual([[null, "", "/jsx-sandbox.html"]]);
    // A refusing environment (or a missing history) must not stop the bridge from working.
    expect(() => startBridge({ hash: `#${NONCE}` })).not.toThrow();
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
    ["source too large", { source: "x".repeat(512 * 1024 + 1) }],
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
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2030-01-01T00:00:10Z"));
    bridge.send({ v: 1, type: "restore-controls" }, "child");
    expect(bridge.posted.at(-1)).toEqual({ v: 1, nonce: NONCE, type: "restore-controls" });
    vi.useRealTimers();
  });

  it("forwards restore-controls only after the child's page started, and at most once a second", () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2030-01-01T00:00:10Z"));
    const bridge = startBridge();
    bridge.send(render());
    const count = (): number => bridge.posted.filter((message) => message["type"] === "restore-controls").length;
    bridge.send({ v: 1, type: "restore-controls" }, "child");
    expect(count()).toBe(0);
    bridge.send({ v: 1, type: "ready" }, "child");
    for (let burst = 0; burst < 20; burst += 1) bridge.send({ v: 1, type: "restore-controls" }, "child");
    expect(count()).toBe(1);
    vi.setSystemTime(new Date("2030-01-01T00:00:11.100Z"));
    bridge.send({ v: 1, type: "restore-controls" }, "child");
    expect(count()).toBe(2);
    vi.useRealTimers();
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

  describe("cap/* relay (installed apps)", () => {
    const request = (op: string, id: string, args: unknown = { key: "prefs/a" }, extra: Record<string, unknown> = {}): Record<string, unknown> => ({ v: 1, type: `cap/${op}`, id, args, ...extra });
    const capPosts = (bridge: ReturnType<typeof startBridge>): Array<Record<string, unknown>> => bridge.posted.filter((message) => typeof message["type"] === "string" && message["type"].startsWith("cap/"));
    const started = (): ReturnType<typeof startBridge> => { const bridge = startBridge(); bridge.send(render()); return bridge; };
    const resultFor = (id: string, result: unknown, overrides: Record<string, unknown> = {}): Record<string, unknown> => ({ v: 1, type: "cap/result", nonce: NONCE, id, result, ...overrides });
    const childInbox = (bridge: ReturnType<typeof startBridge>): Array<Record<string, unknown>> => bridge.childPosted;

    it("forwards a known call from its own child to its parent as {type, body:{id,args}} under the nonce", () => {
      const bridge = started();
      bridge.send(request("kv.get", "1"), "child");
      expect(capPosts(bridge)).toEqual([{ v: 1, nonce: NONCE, type: "cap/kv.get", body: { id: "1", args: { key: "prefs/a" } } }]);
    });

    it("forwards only the six operations, from the child, with exactly the keys {v,type,id,args}", () => {
      const bridge = started();
      ["kv.get", "kv.put", "kv.list", "kv.del", "sql.query", "sql.execute"].forEach((op, index) => {
        bridge.send(request(op, String(index + 1)), "child");
        bridge.send(resultFor(String(index + 1), { ok: true }));
      });
      expect(capPosts(bridge).map((message) => message["type"])).toEqual(["cap/kv.get", "cap/kv.put", "cap/kv.list", "cap/kv.del", "cap/sql.query", "cap/sql.execute"]);
      const before = capPosts(bridge).length;
      // Unknown operations, other services, traversal in the name.
      for (const op of ["vault.get", "delegation.create", "kv.get/../x", "storage.get", "result", "kv.GET", ""]) bridge.send(request(op, "90"), "child");
      // Wrong sender, origin, version.
      bridge.send(request("kv.get", "91"), "other");
      bridge.send(request("kv.get", "92"), "parent");
      bridge.send(request("kv.get", "93"), "child", "https://share.tinycloud.xyz");
      bridge.send({ ...request("kv.get", "94"), v: 2 }, "child");
      // Extra keys, including a nonce or a body the child tries to supply.
      bridge.send(request("kv.get", "95", { key: "a" }, { nonce: NONCE }), "child");
      bridge.send(request("kv.get", "96", { key: "a" }, { body: {} }), "child");
      bridge.send(request("kv.get", "97", { key: "a" }, { origin: "x" }), "child");
      const { args: _args, ...noArgs } = request("kv.get", "98");
      bridge.send(noArgs, "child");
      expect(capPosts(bridge)).toHaveLength(before);
    });

    it("drops a request before the page exists, and one with no usable id (there is nobody to answer)", () => {
      const early = startBridge();
      early.send(request("kv.get", "1"), "child");
      expect(capPosts(early)).toEqual([]);
      const bridge = started();
      for (const id of ["", "x", "1a", "-1", "1234567890", "__proto__", 5, null, undefined]) bridge.send(request("kv.get", id as string), "child");
      expect(capPosts(bridge)).toEqual([]);
      expect(childInbox(bridge)).toEqual([]);
    });

    it("answers a malformed or oversize call itself, without forwarding it", () => {
      const bridge = started();
      bridge.send(request("kv.get", "1", "not an object"), "child");
      bridge.send(request("kv.get", "2", [1, 2]), "child");
      bridge.send(request("kv.put", "3", { key: "a", body: "x".repeat(1_000_001) }), "child");
      bridge.send(request("kv.put", "4", { key: "a", body: new Uint8Array(1_000_001) }), "child");
      bridge.send(request("kv.get", "5", { key: () => 1 }), "child");
      bridge.send(request("kv.get", "6", { key: new Date() }), "child");
      const nested: Record<string, unknown> = {};
      nested["self"] = nested;
      bridge.send(request("kv.get", "7", nested), "child");
      expect(capPosts(bridge)).toEqual([]);
      expect(childInbox(bridge).map((message) => [message["id"], (message["result"] as { error: { code: string } }).error.code])).toEqual([
        ["1", "BAD_REQUEST"], ["2", "BAD_REQUEST"], ["3", "TOO_LARGE"], ["4", "TOO_LARGE"], ["5", "BAD_REQUEST"], ["6", "BAD_REQUEST"], ["7", "BAD_REQUEST"],
      ]);
      expect(childInbox(bridge).every((message) => message["type"] === "cap/result" && message["v"] === 1 && Object.keys(message).sort().join() === "id,result,type,v")).toBe(true);
    });

    it("lets four calls be in flight and answers the fifth BUSY itself; an answer frees a slot", () => {
      const bridge = started();
      for (let id = 1; id <= 5; id += 1) bridge.send(request("kv.get", String(id)), "child");
      expect(capPosts(bridge)).toHaveLength(4);
      expect(childInbox(bridge)).toEqual([{ v: 1, type: "cap/result", id: "5", result: { ok: false, error: { code: "BUSY", message: expect.stringContaining("4 calls") } } }]);
      bridge.send(resultFor("2", { ok: true }));
      bridge.send(request("kv.get", "6"), "child");
      expect(capPosts(bridge)).toHaveLength(5);
      // The same id again while it runs is dropped.
      bridge.send(request("kv.get", "6"), "child");
      expect(capPosts(bridge)).toHaveLength(5);
    });

    it("passes the parent's answer to the child, for a pending id only, from the parent only, under the nonce", () => {
      const bridge = started();
      bridge.send(request("kv.get", "1"), "child");
      const answer = { ok: true, bytes: new Uint8Array([1, 2]), contentType: "text/plain" };
      // Wrong sender, nonce, version, type, extra keys, unknown id, malformed result.
      bridge.send(resultFor("1", answer), "child");
      bridge.send(resultFor("1", answer), "other");
      bridge.send(resultFor("1", answer, { nonce: "f".repeat(32) }));
      bridge.send(resultFor("1", answer, { v: 2 }));
      bridge.send(resultFor("1", answer, { type: "cap/results" }));
      bridge.send(resultFor("1", answer, { extra: 1 }));
      bridge.send(resultFor("2", answer));
      bridge.send(resultFor("1", "ok"));
      bridge.send(resultFor("1", { ok: "yes" }));
      bridge.send(resultFor("1", [true]));
      expect(childInbox(bridge)).toEqual([]);
      bridge.send(resultFor("1", answer));
      expect(childInbox(bridge)).toEqual([{ v: 1, type: "cap/result", id: "1", result: answer }]);
      // Once only.
      bridge.send(resultFor("1", answer));
      expect(childInbox(bridge)).toHaveLength(1);
    });

    it("refuses to relay an answer larger than the cap or one that is not plain data", () => {
      const bridge = started();
      bridge.send(request("kv.get", "1"), "child");
      bridge.send(request("kv.get", "2"), "child");
      bridge.send(resultFor("1", { ok: true, bytes: new Uint8Array(1_000_001) }));
      bridge.send(resultFor("2", { ok: true, value: () => 1 }));
      expect(childInbox(bridge).map((message) => (message["result"] as { error: { code: string } }).error.code)).toEqual(["TOO_LARGE", "INTERNAL"]);
    });

    it("an answer is accepted again only for a call made after the child was replaced", () => {
      const bridge = started();
      bridge.send(request("kv.get", "1"), "child");
      bridge.fireChildLoad();
      bridge.fireChildLoad();
      expect(bridge.child()).toBeNull();
      bridge.send(resultFor("1", { ok: true }));
      expect(childInbox(bridge)).toEqual([]);
    });

    it("nothing a call carries reaches the child as anything but plain data: no nonce, no parent reference", () => {
      const bridge = started();
      bridge.send(request("kv.get", "1"), "child");
      bridge.send(resultFor("1", { ok: true }));
      expect(JSON.stringify(childInbox(bridge))).not.toContain(NONCE);
    });
  });
});
