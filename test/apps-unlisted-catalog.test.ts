import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { expect, it } from "vitest";
import { verifyCatalog } from "../scripts/apps-catalog.mjs";

it("validates the unlisted field and keeps it on the current pin when re-vendoring", () => {
  const work = mkdtempSync("/var/tmp/apps-unlisted-catalog-");
  try {
    const source = join(work, "source");
    const bundle = join(source, "app");
    const publicDir = join(work, "public");
    const catalogPath = join(work, "catalog.json");
    const url = "https://example.test/unlisted-app.git";
    mkdirSync(bundle, { recursive: true });

    const git = (...args: string[]): string =>
      execFileSync("git", args, { cwd: source, encoding: "utf8" }).trim();
    const commit = (description: string): string => {
      writeFileSync(join(bundle, "manifest.json"), JSON.stringify({
        app_id: "test.unlisted", name: "Notebook", description, defaults: false,
      }));
      writeFileSync(join(bundle, "app.jsx"), "export default function App() { return null; }\n");
      git("add", "app");
      git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.test", "commit", "-qm", description);
      return git("rev-parse", "HEAD");
    };
    const vendor = (ref: string): void => {
      execFileSync(process.execPath, [
        "scripts/vendor-app.mjs", url + "@" + ref, "--path", "app",
        "--catalog", catalogPath, "--public", publicDir, "--publisher", "Fixture",
      ], {
        env: {
          ...process.env,
          TMPDIR: work,
          GIT_CONFIG_COUNT: "1",
          GIT_CONFIG_KEY_0: "url.file://" + source + ".insteadOf",
          GIT_CONFIG_VALUE_0: url,
        },
      });
    };
    const read = () => JSON.parse(readFileSync(catalogPath, "utf8"));

    git("init", "-q");
    vendor(commit("First bundle"));
    const catalog = read();
    expect(catalog.apps[0].unlisted).toBeUndefined();
    expect(verifyCatalog(catalog, publicDir)).toEqual([]);
    for (const invalid of [false, null, 1, "true"]) {
      catalog.apps[0].unlisted = invalid;
      expect(verifyCatalog(catalog, publicDir)).toEqual([
        "test.unlisted: unlisted must be true when present",
      ]);
    }
    catalog.apps[0].unlisted = true;
    expect(verifyCatalog(catalog, publicDir)).toEqual([]);
    writeFileSync(catalogPath, JSON.stringify(catalog));
    const second = commit("Second bundle");
    vendor(second);
    const updated = read();
    expect(updated.apps).toHaveLength(2);
    expect(updated.apps[0]).toMatchObject({ unlisted: true, source: { commit: second } });
    expect(updated.apps[1]).toEqual(catalog.apps[0]);
    expect(verifyCatalog(updated, publicDir)).toEqual([]);
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
});
