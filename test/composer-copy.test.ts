import { describe, expect, it } from "vitest";
import { copySelectedSource, uploadSelectedFiles } from "../src/share/composer.js";
import type { ShareTinyCloud } from "../src/share/openkey-session.js";

interface StoredEntry {
  readonly data: Uint8Array;
  readonly contentType: string;
}

function fakeTinyCloud(entries: Record<string, StoredEntry>): { tinycloud: ShareTinyCloud; store: Map<string, StoredEntry> } {
  const store = new Map(Object.entries(entries));
  const kv = {
    get: async (key: string, options?: { binary?: boolean }) => {
      if (options?.binary !== true) throw new Error("copy must request binary reads to preserve exact bytes");
      const stored = store.get(key);
      if (stored === undefined) return { ok: false as const, error: { code: "NOT_FOUND", message: "missing" } };
      return { ok: true as const, data: { data: stored.data, headers: { contentType: stored.contentType } } };
    },
    put: async (key: string, value: Uint8Array, options?: { contentType?: string }) => {
      store.set(key, { data: value, contentType: options?.contentType ?? "application/octet-stream" });
      return { ok: true as const, data: undefined };
    },
    list: async ({ path }: { path: string; limit: number }) => {
      const prefix = `${path}/`;
      const keys = [...store.keys()].filter((key) => key.startsWith(prefix));
      return { ok: true as const, data: { keys, truncated: false } };
    },
  };
  const tinycloud = { kvForSpace: () => kv } as unknown as ShareTinyCloud;
  return { tinycloud, store };
}

describe("copySelectedSource (share byte-for-byte copy)", () => {
  it("copies an existing exact file with real content bytes and its content type", async () => {
    const original = new Uint8Array([1, 2, 3, 4, 250, 251, 252]);
    const { tinycloud, store } = fakeTinyCloud({ "library/report.pdf": { data: original, contentType: "application/pdf" } });

    await copySelectedSource(tinycloud, "share", "library/report.pdf", "exact", "shares/abc/report.pdf");

    const copied = store.get("shares/abc/report.pdf");
    expect(copied).toBeDefined();
    expect(copied?.data).toEqual(original);
    expect(copied?.data.byteLength).toBeGreaterThan(0);
    expect(copied?.contentType).toBe("application/pdf");
  });

  it("copies the complete nested folder tree with real bytes while excluding siblings", async () => {
    const childA = new Uint8Array([10, 20, 30]);
    const childB = new Uint8Array([40, 50, 60, 70]);
    const nested = new Uint8Array([99]);
    const sibling = new Uint8Array([1]);
    const { tinycloud, store } = fakeTinyCloud({
      "library/docs/a.md": { data: childA, contentType: "text/markdown" },
      "library/docs/b.txt": { data: childB, contentType: "text/plain" },
      "library/docs/nested/c.md": { data: nested, contentType: "text/markdown" },
      "library/other/sibling.md": { data: sibling, contentType: "text/markdown" },
    });

    await copySelectedSource(tinycloud, "share", "library/docs", "prefix", "shares/xyz");

    expect(store.get("shares/xyz/a.md")?.data).toEqual(childA);
    expect(store.get("shares/xyz/a.md")?.contentType).toBe("text/markdown");
    expect(store.get("shares/xyz/b.txt")?.data).toEqual(childB);
    expect(store.get("shares/xyz/b.txt")?.contentType).toBe("text/plain");
    expect(store.get("shares/xyz/nested/c.md")?.data).toEqual(nested);
    expect(store.get("shares/xyz/nested/c.md")?.contentType).toBe("text/markdown");
    // Out-of-prefix siblings are never copied.
    expect(store.has("shares/xyz/nested")).toBe(false);
    expect(store.has("shares/xyz/sibling.md")).toBe(false);
    // Only files were written; no empty placeholder for the folder itself.
    const copiedKeys = [...store.keys()].filter((key) => key.startsWith("shares/xyz"));
    expect(copiedKeys.sort()).toEqual(["shares/xyz/a.md", "shares/xyz/b.txt", "shares/xyz/nested/c.md"]);
  });

  it("does not substitute an unrelated path when the requested source is missing", async () => {
    const { tinycloud } = fakeTinyCloud({});
    await expect(copySelectedSource(tinycloud, "share", "library/missing.md", "exact", "shares/abc/missing.md")).rejects.toThrow();
  });
});

describe("uploadSelectedFiles", () => {
  it("stores every selected file as a distinct direct child of the delegated prefix", async () => {
    const { tinycloud, store } = fakeTinyCloud({});
    await uploadSelectedFiles(tinycloud, "share", "shares/folder-id", "prefix", [
      new File([new Uint8Array([1, 2, 3])], "one.bin", { type: "application/octet-stream" }),
      new File(["two"], "two.txt", { type: "text/plain" }),
    ]);

    expect([...store.keys()].sort()).toEqual(["shares/folder-id/one.bin", "shares/folder-id/two.txt"]);
    expect(store.get("shares/folder-id/one.bin")?.data).toEqual(new Uint8Array([1, 2, 3]));
    expect(Array.from(store.get("shares/folder-id/two.txt")?.data ?? [])).toEqual(Array.from(new TextEncoder().encode("two")));
    expect(store.get("shares/folder-id/two.txt")?.contentType).toBe("text/plain");
  });

  it("preserves canonical nested paths selected from a browser folder", async () => {
    const index = new File(["<h1>Artifact</h1>"], "index.html", { type: "text/html" });
    const script = new File(["document.body.dataset.ready='yes'"], "app.js", { type: "text/javascript" });
    Object.defineProperty(index, "webkitRelativePath", { value: "demo/index.html" });
    Object.defineProperty(script, "webkitRelativePath", { value: "demo/scripts/app.js" });
    const { tinycloud, store } = fakeTinyCloud({});

    await uploadSelectedFiles(tinycloud, "share", "shares/artifact", "prefix", [index, script]);

    expect([...store.keys()].sort()).toEqual(["shares/artifact/index.html", "shares/artifact/scripts/app.js"]);
  });

  it("keeps one-file uploads exact and refuses a multi-file exact overwrite", async () => {
    const { tinycloud, store } = fakeTinyCloud({});
    await uploadSelectedFiles(tinycloud, "share", "shares/exact/one.txt", "exact", [new File(["one"], "one.txt")]);
    expect([...store.keys()]).toEqual(["shares/exact/one.txt"]);

    await expect(uploadSelectedFiles(tinycloud, "share", "shares/exact/collision.txt", "exact", [
      new File(["a"], "a.txt"),
      new File(["b"], "b.txt"),
    ])).rejects.toThrow();
    expect(store.has("shares/exact/collision.txt")).toBe(false);
  });
});
