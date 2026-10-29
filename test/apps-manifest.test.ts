import { createHash, webcrypto } from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { CatalogEntry } from "../src/apps/catalog.ts";
import { loadManifest } from "../src/apps/manifest.ts";

Object.defineProperty(globalThis, "crypto", { value: webcrypto, configurable: true });

afterEach(() => vi.unstubAllGlobals());

function entry(digest: string, content: string): CatalogEntry {
  const bytes = Buffer.from(content);
  return {
    app_id: "test.manifest-versions",
    name: "Manifest versions",
    description: "Test manifests are version-pinned.",
    publisher: { name: "Tests" },
    source: { repo: "https://example.test/apps", tag: null, commit: "a".repeat(40) },
    manifest: { path: "manifest.json", sha256: createHash("sha256").update(bytes).digest("hex") },
    bundle: { root: `/apps/b/${digest}/`, files: [], digest },
    knowledge: null,
  };
}

describe("catalog manifests by installed version", () => {
  it("loads distinct pinned manifests for two versions of the same app", async () => {
    const oldDigest = "1".repeat(64);
    const newDigest = "2".repeat(64);
    const oldText = JSON.stringify({ version: "old" });
    const newText = JSON.stringify({ version: "new" });
    const fetcher = vi.fn(async (input: RequestInfo | URL) => {
      const body = String(input).includes(oldDigest) ? oldText : newText;
      return new Response(body, { status: 200 });
    });
    vi.stubGlobal("fetch", fetcher);

    const oldEntry = entry(oldDigest, oldText);
    const newEntry = entry(newDigest, newText);
    const oldFirst = await loadManifest(oldEntry);
    const oldAgain = await loadManifest(oldEntry);
    const current = await loadManifest(newEntry);

    expect(oldFirst).toEqual({ ok: true, manifest: { version: "old" } });
    expect(oldAgain).toEqual(oldFirst);
    expect(current).toEqual({ ok: true, manifest: { version: "new" } });
    expect(fetcher).toHaveBeenCalledTimes(2);
  });
});
