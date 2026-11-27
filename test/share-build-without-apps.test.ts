// @vitest-environment node
import { execFile } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { promisify } from "node:util";

import { afterAll, describe, expect, it } from "vitest";

/**
 * Share no longer hosts apps, and the routes that stay still ship: the REAL build output has no app page, runner or
 * bundle, and has /courier (page, script, stylesheet), the viewer, the share form and the landing page.
 */
const ROOT = resolve(import.meta.dirname, "..");
const run = promisify(execFile);
let out = "";

afterAll(() => { if (out !== "") rmSync(out, { recursive: true, force: true }); });

/** The same-origin asset URLs a page names in `src` and `href`. */
const assetsOf = (html: string): string[] => [...html.matchAll(/(?:src|href)="(\/assets\/[^"]+)"/g)].map((match) => match[1]!);

describe("the built site", () => {
  it("serves /courier, /viewer, /share and the landing page, and has no /apps page, runner or bundle", async () => {
    out = mkdtempSync(join(tmpdir(), "share-no-apps-"));
    await run(process.execPath, ["node_modules/vite/bin/vite.js", "build", "--outDir", out, "--emptyOutDir"], { cwd: ROOT, maxBuffer: 64 * 1024 * 1024 });

    for (const page of ["courier/index.html", "viewer/index.html", "share/index.html", "index.html", "how-it-works.html"]) {
      expect(existsSync(join(out, page)), page).toBe(true);
    }
    // /courier's page names a script and a stylesheet that exist in the output.
    const courier = readFileSync(join(out, "courier/index.html"), "utf8");
    const courierAssets = assetsOf(courier);
    expect(courierAssets.some((url) => url.endsWith(".js"))).toBe(true);
    expect(courierAssets.some((url) => url.endsWith(".css"))).toBe(true);
    for (const url of courierAssets) expect(existsSync(join(out, url)), url).toBe(true);

    expect(existsSync(join(out, "apps"))).toBe(false);
    const redirects = readFileSync(join(out, "_redirects"), "utf8");
    expect(redirects).toContain("/courier /courier/ 200");
    expect(redirects).not.toMatch(/\/apps/);
    // The landing page links no apps page.
    expect(readFileSync(join(out, "index.html"), "utf8")).not.toMatch(/href="\/apps/);
  }, 180_000);
});
