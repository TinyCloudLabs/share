// @vitest-environment node
import { execFile } from "node:child_process";
import { mkdtempSync, readFileSync, readdirSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { promisify } from "node:util";

import { afterAll, describe, expect, it } from "vitest";

/**
 * TinyCloud One's origins by build kind, proven on the REAL build output (bundle,
 * pages and `_headers`), not on the helpers: a production build names only
 * https://tinycloud.one; the preview alias exists only when VITE_ONE_BUILD is
 * exactly "preview"; no build carries a localhost origin or a local-run node.
 */
const ROOT = resolve(import.meta.dirname, "..");
const run = promisify(execFile);
const outDirs: string[] = [];
const PREVIEW = "https://feat-one-apps.tinychat.pages.dev";
const FRAMED = ["/courier", "/courier/", "/courier/*"];
const LOCAL_NODE = "http://127.0.0.1:18799";

async function build(oneBuild: string | undefined): Promise<string> {
  const outDir = mkdtempSync(join(tmpdir(), "courier-one-"));
  outDirs.push(outDir);
  const env: NodeJS.ProcessEnv = { ...process.env, COURIER_DEV_NODE: LOCAL_NODE };
  delete env["VITE_ONE_BUILD"];
  if (oneBuild !== undefined) env["VITE_ONE_BUILD"] = oneBuild;
  await run(process.execPath, ["node_modules/vite/bin/vite.js", "build", "--outDir", outDir, "--emptyOutDir"], { cwd: ROOT, env, maxBuffer: 64 * 1024 * 1024 });
  return outDir;
}

function listAll(dir: string): string[] {
  return readdirSync(dir).flatMap((entry) => {
    const path = join(dir, entry);
    return statSync(path).isDirectory() ? listAll(path) : [path];
  });
}

const textFiles = (dir: string): string[] => listAll(dir).filter((file) => /\.(js|mjs|html|css|json|map)$|_headers$/.test(file));
const sections = (headers: string): string[] => headers.split(/\n\n+/);
const policyOf = (headers: string, route: string): string => (sections(headers).find((section) => section.startsWith(`${route}\n`)) ?? "").split("\n").find((line) => line.trim().startsWith("Content-Security-Policy:")) ?? "";

afterAll(() => { for (const dir of outDirs) rmSync(dir, { recursive: true, force: true }); });

describe("the built /courier and TinyCloud One's origins", () => {
  it("a production build names only tinycloud.one: no pages.dev, no localhost One origin, no local-run node", async () => {
    const out = await build(undefined);
    const files = textFiles(out);
    const offenders = files.filter((file) => /pages\.dev|feat-one-apps|localhost:5186|localhost:5190|127\.0\.0\.1:18799/.test(readFileSync(file, "utf8")));
    expect(offenders).toEqual([]);

    const headers = readFileSync(join(out, "_headers"), "utf8");
    for (const route of FRAMED) {
      expect(policyOf(headers, route), route).toMatch(/; frame-ancestors https:\/\/tinycloud\.one$/);
      expect(policyOf(headers, route), route).not.toContain("*;");
    }
    // The One origin is in the shipped Courier code too (the embed controller's parent list).
    expect(files.filter((file) => file.endsWith(".js") && readFileSync(file, "utf8").includes("https://tinycloud.one")).length).toBeGreaterThan(0);
    // No other route names One.
    const named = sections(headers).filter((section) => section.includes("tinycloud.one")).map((section) => section.split("\n", 1)[0]);
    expect(named).toEqual(FRAMED);
  }, 180_000);

  it("any signal other than exactly 'preview' is still a production build", async () => {
    const out = await build("Preview");
    expect(textFiles(out).filter((file) => readFileSync(file, "utf8").includes("tinychat.pages.dev"))).toEqual([]);
    for (const route of FRAMED) expect(policyOf(readFileSync(join(out, "_headers"), "utf8"), route)).toMatch(/; frame-ancestors https:\/\/tinycloud\.one$/);
  }, 180_000);

  it("a preview build adds only the exact tinychat alias, to the three framed routes and the controller, and still no localhost", async () => {
    const out = await build("preview");
    const headers = readFileSync(join(out, "_headers"), "utf8");
    for (const route of FRAMED) {
      expect(policyOf(headers, route), route).toMatch(new RegExp(`; frame-ancestors https://tinycloud\\.one ${PREVIEW.replaceAll(".", "\\.")}$`));
    }
    const named = sections(headers).filter((section) => section.includes("tinychat.pages.dev")).map((section) => section.split("\n", 1)[0]);
    expect(named).toEqual(FRAMED);
    const files = textFiles(out);
    expect(files.filter((file) => file.endsWith(".js") && readFileSync(file, "utf8").includes(PREVIEW)).length).toBeGreaterThan(0);
    expect(files.filter((file) => /localhost:5186|localhost:5190|127\.0\.0\.1:18799/.test(readFileSync(file, "utf8")))).toEqual([]);
    for (const file of files) expect(readFileSync(file, "utf8").match(/(?:[a-z0-9-]+\.)+pages\.dev/g)?.filter((host) => host !== "feat-one-apps.tinychat.pages.dev") ?? []).toEqual([]);
  }, 180_000);
});
