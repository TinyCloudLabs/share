import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";

import { afterEach, describe, expect, it, vi } from "vitest";

import type { JsxManifest } from "../src/artifact/jsx-runtime/files.js";
import { renderUserContentHeaders, renderViewerHeaders, withUserContentOrigin } from "../src/artifact/user-content/headers.js";
import { loadJsxModules } from "../src/viewer/jsx-modules.js";
import { parseUserContentOrigin, userContentUrl } from "../src/viewer/user-content-origin.js";

const ORIGIN = "https://usercontent.tinycloud.xyz";

describe("user-content origin config", () => {
  it("accepts empty (same origin), an https origin, and a loopback http origin only", () => {
    expect(parseUserContentOrigin(undefined)).toBe("");
    expect(parseUserContentOrigin("  ")).toBe("");
    expect(parseUserContentOrigin(ORIGIN)).toBe(ORIGIN);
    expect(parseUserContentOrigin(`${ORIGIN}/`)).toBe(ORIGIN);
    expect(parseUserContentOrigin("http://127.0.0.1:4321")).toBe("http://127.0.0.1:4321");
  });

  it.each([
    "http://usercontent.tinycloud.xyz",
    "javascript:alert(1)",
    "//usercontent.tinycloud.xyz",
    `${ORIGIN}/sandbox`,
    `${ORIGIN}?x=1`,
    `${ORIGIN}#x`,
    "https://user:pass@usercontent.tinycloud.xyz",
    "not a url",
  ])("refuses %s", (value) => {
    expect(() => parseUserContentOrigin(value)).toThrow();
  });

  it("builds frame and asset URLs from the origin, relative when it is empty", () => {
    expect(userContentUrl("/jsx-sandbox.html#abc", "")).toBe("/jsx-sandbox.html#abc");
    expect(userContentUrl("/jsx-sandbox.html#abc", ORIGIN)).toBe(`${ORIGIN}/jsx-sandbox.html#abc`);
    expect(() => userContentUrl("//evil.example/x", ORIGIN)).toThrow();
    expect(() => userContentUrl("relative", ORIGIN)).toThrow();
  });
});

describe("single-sourced frame and asset URLs", () => {
  const LITERALS = /["'`]\/(?:jsx-sandbox|artifact-sandbox|mermaid-sandbox|assets\/jsx-runtime)/;
  // Only the frame documents define their own path constants (the config module only names them
  // in prose); everything that
  // builds a URL goes through user-content-origin.ts.
  const DEFINERS = new Set(["jsx-frame.ts", "artifact-frame.ts", "mermaid-frame.ts", "user-content-origin.ts"]);

  it("hard-codes no sandbox or runtime path in the viewer outside the frame definitions", () => {
    const offenders: string[] = [];
    const walk = (dir: string): void => {
      for (const entry of readdirSync(dir)) {
        const path = join(dir, entry);
        if (statSync(path).isDirectory()) walk(path);
        else if (/\.ts$/.test(entry) && !DEFINERS.has(entry) && LITERALS.test(readFileSync(path, "utf8"))) offenders.push(path);
      }
    };
    walk("src/viewer");
    // The build and header code names the paths on purpose: it produces the files.
    expect(offenders).toEqual([]);
  });

  it.each(["artifact-sandbox.ts", "jsx-sandbox.ts", "mermaid-sandbox.ts"])("%s sets its frame src through userContentUrl and never allows same-origin", (file) => {
    const source = readFileSync(join("src/viewer", file), "utf8");
    expect(source).toMatch(/setAttribute\("src", userContentUrl\(/);
    expect(source).toContain('setAttribute("sandbox", "allow-scripts")');
    expect(source).not.toMatch(/setAttribute\(\s*["']sandbox["']\s*,\s*["'][^"']*allow-same-origin/);
  });

  it("sets the frame src from the configured origin when one is set", async () => {
    vi.stubEnv("VITE_USER_CONTENT_ORIGIN", ORIGIN);
    vi.resetModules();
    const { createJsxSandbox } = await import("../src/viewer/jsx-sandbox.js");
    const { createArtifactSandbox } = await import("../src/viewer/artifact-sandbox.js");
    const { createMermaidSandbox } = await import("../src/viewer/mermaid-sandbox.js");
    const frames = [createJsxSandbox(document).iframe, createArtifactSandbox(document).iframe];
    createMermaidSandbox(document);
    frames.push(document.querySelector<HTMLIFrameElement>("iframe.mermaid-sandbox")!);
    for (const frame of frames) {
      expect(frame.getAttribute("src")!.startsWith(`${ORIGIN}/`)).toBe(true);
      expect(frame.getAttribute("sandbox")).toBe("allow-scripts");
      expect(new URL(frame.src).hash).toMatch(/^#[0-9a-f]{32}$/);
    }
    document.body.replaceChildren();
  });

  afterEach(() => { vi.unstubAllEnvs(); vi.resetModules(); });
});

describe("module files from a user-content origin", () => {
  const body = '__TC_DEFINE__(["x"],function(){});';
  const manifest = (digest: string): JsxManifest => ({
    version: 1,
    files: Object.fromEntries(["react", "react-dom", "runtime", "tailwind"].map((id) => [id, { id, url: `/assets/jsx-runtime/${id}.js`, sha256: digest, bytes: body.length, provides: [id] }])),
  });

  it("fetches with CORS, no credentials, no referrer, from the configured origin, and still checks the digest", async () => {
    const { createHash } = await import("node:crypto");
    const good = createHash("sha256").update(body).digest("hex");
    const calls: Array<{ url: string; init: RequestInit }> = [];
    const fetchImpl = (async (url: string, init: RequestInit) => { calls.push({ url, init }); return new Response(body); }) as unknown as typeof fetch;
    await loadJsxModules(manifest(good), "x", { fetch: fetchImpl, userContentOrigin: ORIGIN });
    expect(calls.length).toBe(4);
    for (const { url, init } of calls) {
      expect(url.startsWith(`${ORIGIN}/assets/jsx-runtime/`)).toBe(true);
      expect(init).toMatchObject({ mode: "cors", credentials: "omit", referrerPolicy: "no-referrer" });
    }
    // A host that serves other bytes is refused whatever it claims.
    await expect(loadJsxModules(manifest("0".repeat(64)), "x", { fetch: fetchImpl, userContentOrigin: ORIGIN })).rejects.toThrow(/sha256 differs/);
  });
});

describe("viewer and user-content header files", () => {
  const template = readFileSync("public/_headers", "utf8");

  it("leaves the same-origin headers untouched when no origin is set", () => {
    expect(renderViewerHeaders(template, "")).toBe(template);
  });

  it("with an origin: names exactly that origin in frame-src and connect-src, and drops every sandbox route", () => {
    const rendered = renderViewerHeaders(template, ORIGIN);
    const siteWide = /^\/\*\n([\s\S]*?)\n\n/.exec(rendered)![1]!;
    const csp = /Content-Security-Policy: (.*)/.exec(siteWide)![1]!;
    expect(csp).toContain(`frame-src 'self' ${ORIGIN} https://openkey.so`);
    expect(csp).toContain(`connect-src 'self' ${ORIGIN} https:`);
    expect(csp).toContain("frame-ancestors 'none'");
    expect(csp).toContain("script-src 'self' 'wasm-unsafe-eval'");
    for (const route of ["/jsx-sandbox", "/jsx-sandbox.html", "/artifact-sandbox", "/artifact-sandbox.html", "/mermaid-sandbox", "/mermaid-sandbox.html"]) {
      expect(rendered).not.toContain(`\n${route}\n`);
    }
    expect(rendered).toContain("/assets/*");
  });

  it("matches the viewer page's meta policy on frame-src and connect-src", () => {
    const meta = /<meta http-equiv="Content-Security-Policy" content="([^"]*)"/.exec(readFileSync("viewer/index.html", "utf8"))![1]!;
    const header = /Content-Security-Policy: (.*)/.exec(template)![1]!;
    const directive = (policy: string, name: string): string => policy.split("; ").find((part) => part.startsWith(`${name} `))!;
    for (const name of ["frame-src", "connect-src"]) {
      expect(directive(withUserContentOrigin(meta, ORIGIN), name)).toBe(directive(withUserContentOrigin(header, ORIGIN), name));
      expect(directive(meta, name)).toBe(directive(header, name));
    }
  });

  it("is idempotent and leaves other directives alone", () => {
    const once = withUserContentOrigin("default-src 'none'; connect-src 'self' https:; frame-src 'self'", ORIGIN);
    expect(once).toBe(`default-src 'none'; connect-src 'self' ${ORIGIN} https:; frame-src 'self' ${ORIGIN}`);
    expect(withUserContentOrigin(once, ORIGIN)).toBe(once);
  });

  it("user-content headers: frame-ancestors is the viewer origin, never 'self', no X-Frame-Options, CORS only on the library files", () => {
    const text = renderUserContentHeaders("https://share.tinycloud.xyz");
    expect(text).not.toMatch(/frame-ancestors 'self'/i);
    expect(text).not.toMatch(/x-frame-options/i);
    expect(text).not.toMatch(/set-cookie|authorization/i);
    expect(text.match(/frame-ancestors https:\/\/share\.tinycloud\.xyz/g)?.length).toBe(6);
    expect(text.match(/Access-Control-Allow-Origin: .*/g)).toEqual(Array(2).fill("Access-Control-Allow-Origin: https://share.tinycloud.xyz"));
    expect(text).not.toContain("Access-Control-Allow-Origin: *");
    expect(text).toContain("Referrer-Policy: no-referrer");
    expect(text).toContain("Cache-Control: public, max-age=31536000, immutable");
  });
});
