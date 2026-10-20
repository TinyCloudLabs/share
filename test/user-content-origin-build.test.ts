// @vitest-environment node
import { execFile } from "node:child_process";
import { mkdtempSync, readFileSync, readdirSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { promisify } from "node:util";

import { afterAll, describe, expect, it } from "vitest";

/**
 * The production viewer is built with `vite build` (Cloudflare Pages: `npm run
 * build:deploy`) and `VITE_USER_CONTENT_ORIGIN` in the process env. The unit tests
 * exercise `parseUserContentOrigin` and the e2e runs the dev server, so only this
 * test proves that the BUILT output agrees with itself: the viewer's CSP (meta tag
 * and `_headers`) and the viewer's JS must name the same origin, and with no
 * origin configured nothing names one.
 */
const ORIGIN = "https://usercontent.tinycloud.xyz";
const ROOT = resolve(import.meta.dirname, "..");
const run = promisify(execFile);
const outDirs: string[] = [];

async function build(origin: string | undefined): Promise<string> {
  const outDir = mkdtempSync(join(tmpdir(), "viewer-origin-"));
  outDirs.push(outDir);
  const env: NodeJS.ProcessEnv = { ...process.env };
  delete env["VITE_USER_CONTENT_ORIGIN"];
  if (origin !== undefined) env["VITE_USER_CONTENT_ORIGIN"] = origin;
  await run(process.execPath, ["node_modules/vite/bin/vite.js", "build", "--outDir", outDir, "--emptyOutDir"], { cwd: ROOT, env, maxBuffer: 64 * 1024 * 1024 });
  return outDir;
}

function listAll(dir: string): string[] {
  return readdirSync(dir).flatMap((entry) => {
    const path = join(dir, entry);
    return statSync(path).isDirectory() ? listAll(path) : [path];
  });
}

afterAll(() => { for (const dir of outDirs) rmSync(dir, { recursive: true, force: true }); });

describe("built viewer and the user-content origin", () => {
  it("bakes the origin into the viewer's JS, and its CSP (meta tag and _headers) names the same origin", async () => {
    const out = await build(ORIGIN);
    const files = listAll(out);
    const js = files.filter((file) => file.endsWith(".js"));

    // The constant lives in the shared chunk the viewer imports, not necessarily in viewer-*.js.
    const withOrigin = js.filter((file) => readFileSync(file, "utf8").includes(`"${ORIGIN}"`));
    expect(withOrigin.length).toBeGreaterThan(0);
    expect(withOrigin.some((file) => readFileSync(file, "utf8").includes("VITE_USER_CONTENT_ORIGIN must be an https origin"))).toBe(true);

    const meta = /<meta http-equiv="Content-Security-Policy" content="([^"]*)"/.exec(readFileSync(join(out, "viewer/index.html"), "utf8"))?.[1] ?? "";
    for (const directive of ["frame-src", "connect-src"]) {
      expect(new RegExp(`${directive}[^;]*${ORIGIN}`).test(meta), `meta ${directive}`).toBe(true);
    }
    const headers = readFileSync(join(out, "_headers"), "utf8");
    for (const directive of ["frame-src", "connect-src"]) {
      expect(new RegExp(`Content-Security-Policy:[^\\n]*${directive}[^;\\n]*${ORIGIN}`).test(headers), `_headers ${directive}`).toBe(true);
    }
  }, 180_000);

  it("names no user-content origin anywhere when none is configured", async () => {
    const out = await build(undefined);
    expect(listAll(out).filter((file) => readFileSync(file, "utf8").includes("usercontent.tinycloud.xyz"))).toEqual([]);
  }, 180_000);
});
