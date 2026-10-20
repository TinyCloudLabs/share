// @vitest-environment node
import { mkdtempSync, readFileSync, readdirSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { buildJsxRuntime } from "../src/artifact/jsx-runtime/build.js";
import { SANDBOX_DOCUMENTS } from "../src/artifact/user-content/headers.js";
import { buildUserContent } from "../src/artifact/user-content/build.js";

const VIEWER = "https://share.tinycloud.xyz";
let outDir: string;
let files: readonly string[];

beforeAll(async () => {
  outDir = mkdtempSync(join(tmpdir(), "usercontent-"));
  ({ files } = await buildUserContent({ outDir, viewerOrigin: VIEWER }));
}, 120_000);
afterAll(() => { rmSync(outDir, { recursive: true, force: true }); });

function listAll(dir: string, prefix = ""): string[] {
  return readdirSync(dir).flatMap((entry) => {
    const path = join(dir, entry);
    return statSync(path).isDirectory() ? listAll(path, `${prefix}${entry}/`) : [`${prefix}${entry}`];
  }).sort();
}

describe("user-content build target", () => {
  it("contains only the sandbox documents, the library files, their manifest and notice, and _headers", async () => {
    const runtime = await buildJsxRuntime();
    const expected = [
      "NOTICE.txt",
      "_headers",
      "artifact-sandbox.html",
      "jsx-sandbox.html",
      "mermaid-sandbox.html",
      "manifest.json",
      ...runtime.files.map((file) => file.fileName),
    ].sort();
    expect(listAll(outDir)).toEqual(expected);
    expect(files).toEqual(expected);
  });

  it("publishes the manifest the viewer embeds, and the files match its digests", async () => {
    const runtime = await buildJsxRuntime();
    expect(JSON.parse(readFileSync(join(outDir, "manifest.json"), "utf8"))).toEqual(runtime.manifest);
    for (const file of Object.values(runtime.manifest.files)) {
      expect(readFileSync(join(outDir, file.url)).byteLength).toBe(file.bytes);
    }
  });

  it("serves every document with the CSP its meta tag carries, plus frame-ancestors for the viewer only", () => {
    const headers = readFileSync(join(outDir, "_headers"), "utf8");
    for (const doc of SANDBOX_DOCUMENTS) {
      const html = readFileSync(join(outDir, doc.path.slice(1)), "utf8");
      const meta = /<meta http-equiv="Content-Security-Policy" content="([^"]*)"/.exec(html);
      expect(meta?.[1], doc.path).toBe(doc.csp);
      for (const route of [doc.path, doc.path.replace(/\.html$/, "")]) {
        expect(headers).toContain(`\n${route}\n  ! Content-Security-Policy\n  Content-Security-Policy: ${doc.csp}; frame-ancestors ${VIEWER}\n`);
      }
    }
  });

  it("holds no credentials surface: no cookies, no API, no viewer code, nothing but static files", () => {
    const headers = readFileSync(join(outDir, "_headers"), "utf8");
    expect(headers).not.toMatch(/set-cookie|authorization|x-frame-options/i);
    expect(listAll(outDir).filter((name) => /\.(?:html|js)$/.test(name) && !/^(?:jsx|artifact|mermaid)-sandbox\.html$|^assets\/jsx-runtime\//.test(name))).toEqual([]);
    // The mermaid document embeds the (third-party) library, whose own text mentions sandbox tokens.
    for (const path of ["jsx-sandbox.html", "artifact-sandbox.html"]) {
      expect(readFileSync(join(outDir, path), "utf8"), path).not.toMatch(/allow-same-origin/);
    }
  });

  it("detaches Pages' default wildcard CORS and names the viewer on the library files and manifest only", () => {
    const headers = readFileSync(join(outDir, "_headers"), "utf8");
    const sections = headers.trim().split(/\n{2,}/);
    const withCors = sections.filter((section) => /Access-Control-Allow-Origin: /.test(section)).map((section) => section.split("\n", 1)[0]);
    expect(withCors).toEqual(["/assets/jsx-runtime/*", "/manifest.json"]);
    expect(sections[0]!.split("\n").slice(0, 2)).toEqual(["/*", "  ! Access-Control-Allow-Origin"]);
    expect(headers).not.toContain("Access-Control-Allow-Origin: *");
    expect(headers.match(/Access-Control-Allow-Origin: .*/g)).toEqual([`Access-Control-Allow-Origin: ${VIEWER}`, `Access-Control-Allow-Origin: ${VIEWER}`]);
    // Placeholder headers survive, and each sandbox document detaches the site-wide CSP before setting its own.
    for (const kept of ["Cross-Origin-Opener-Policy: same-origin", "Referrer-Policy: no-referrer", "X-Content-Type-Options: nosniff", "Permissions-Policy: camera=()", "Cache-Control: no-cache"]) expect(headers).toContain(kept);
    for (const doc of SANDBOX_DOCUMENTS) expect(headers).toContain(`${doc.path}\n  ! Content-Security-Policy\n`);
  });

  it("ships static files Cloudflare's zone-wide rewriters have nothing to rewrite in", () => {
    // Email Obfuscation rewrites address-looking text in HTML. The pattern is the
    // standard local@domain.tld shape; mermaid's own markdown regex source contains
    // "(@)" fragments and `package@8.2.0/` path comments that a looser \S+@\S+\.\S+ lint
    // would flag but that are not addresses (the TLD must be letters).
    const email = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b/;
    for (const path of ["jsx-sandbox.html", "artifact-sandbox.html", "mermaid-sandbox.html"]) {
      expect(readFileSync(join(outDir, path), "utf8"), path).not.toMatch(email);
    }
    for (const name of listAll(outDir).filter((entry) => entry.endsWith(".js"))) {
      expect(readFileSync(join(outDir, name), "utf8"), name).not.toMatch(email);
    }
  });

  it("references no cookie in anything shipped, and no HTML depends on an injected script", () => {
    for (const name of listAll(outDir)) {
      if (name === "_headers" || name === "NOTICE.txt") continue;
      const text = readFileSync(join(outDir, name), "utf8");
      expect(text, name).not.toMatch(/document\.cookie|set-cookie|cookieStore/i);
      if (name.endsWith(".html")) {
        expect(text, name).not.toMatch(/<script[^>]+src=/i);
        expect(text, name).not.toMatch(/cdn-cgi/i);
      }
    }
  });
});
