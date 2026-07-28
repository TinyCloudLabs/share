import { describe, expect, it } from "vitest";
import { classifyContent, MAX_SAFE_CONTENT_BYTES, renderSafeContent } from "../src/viewer/content.js";
import { directChildren, normalizeFolderPage } from "../src/viewer/folder.js";
import { canEdit, ShareEditor } from "../src/viewer/editor.js";

describe("adaptive viewer adapters", () => {
  it("never previews HTML or SVG as executable content", () => {
    expect(classifyContent({ mediaType: "text/html", filename: "page.html", byteLength: 1 })).toBe("download");
    expect(classifyContent({ mediaType: "image/svg+xml", filename: "image.svg", byteLength: 1 })).toBe("download");
    expect(canEdit("text/html", ["edit"])).toBe(false);
  });

  it("downgrades oversized and invalid UTF-8 text to an explicit download", async () => {
    Object.defineProperty(URL, "createObjectURL", { configurable: true, value: () => "blob:viewer-test" });
    Object.defineProperty(URL, "revokeObjectURL", { configurable: true, value: () => undefined });
    const root = document.createElement("main");
    const oversized = new Uint8Array(MAX_SAFE_CONTENT_BYTES + 1);
    expect(await renderSafeContent(root, oversized, { mediaType: "text/markdown", filename: "large.md", byteLength: 1 })).toBe("download");
    expect(root.textContent).toContain("This file can't be previewed here");
    expect(await renderSafeContent(root, Uint8Array.from([0xff, 0xfe]), { mediaType: "text/plain", filename: "bad.txt", byteLength: 2 })).toBe("download");
    expect(root.querySelector("a")?.textContent).toBe("Download file");
  });

  it("projects only direct folder children and deduplicates folders", () => {
    expect(directChildren([{ path: "root/a.md", kind: "file" }, { path: "root/f/b.md", kind: "file" }, { path: "root/f/c.md", kind: "file" }, { path: "root/z.md", kind: "file" }], "root/")).toEqual([{ path: "root/a.md", kind: "file" }, { path: "root/f", kind: "folder" }, { path: "root/z.md", kind: "file" }]);
  });

  it("normalizes the native paths response without trusting folder kinds", () => {
    expect(normalizeFolderPage({ paths: ["docs/a.md", { path: "docs/sub/", kind: "folder" }], nextCursor: "opaque" })).toEqual({ entries: [{ path: "docs/a.md", kind: "file" }, { path: "docs/sub/", kind: "folder" }], nextCursor: "opaque" });
    expect(() => normalizeFolderPage({ paths: [42] })).toThrow("folder entry is invalid");
  });

  it("keeps a stale draft after a save conflict", async () => {
    const client = { save: async () => { throw Object.assign(new Error("precondition failed"), { status: 412 }); }, reload: async () => ({ bytes: new TextEncoder().encode("fresh"), etag: "new", mediaType: "text/markdown" }) };
    const editor = new ShareEditor({ bytes: new TextEncoder().encode("draft"), etag: "old", mediaType: "text/markdown" }, client);
    editor.setDraft(new TextEncoder().encode("local draft"));
    await expect(editor.save()).rejects.toThrow("precondition failed");
    expect(new TextDecoder().decode(editor.value)).toBe("local draft");
    expect(editor.currentState).toBe("conflict");
  });

  it("updates the CAS baseline after save and reload", async () => {
    const ifMatches: string[] = [];
    const client = {
      save: async (_bytes: Uint8Array, ifMatch: string) => { ifMatches.push(ifMatch); return { etag: "new" }; },
      reload: async () => ({ bytes: new TextEncoder().encode("fresh"), etag: "fresh-etag", mediaType: "text/markdown" }),
    };
    const editor = new ShareEditor({ bytes: new TextEncoder().encode("draft"), etag: "old", mediaType: "text/markdown" }, client);
    editor.setDraft(new TextEncoder().encode("first"));
    await editor.save();
    editor.setDraft(new TextEncoder().encode("second"));
    await editor.save();
    await editor.reload();
    editor.setDraft(new TextEncoder().encode("third"));
    await editor.save();
    expect(ifMatches).toEqual(["old", "new", "fresh-etag"]);
  });
});
