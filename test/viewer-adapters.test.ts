import { describe, expect, it } from "vitest";
import { classifyContent, HTML_FRAME_CLASS, MAX_SAFE_CONTENT_BYTES, renderSafeContent } from "../src/viewer/content.js";
import { ARTIFACT_SANDBOX_PATH, type ArtifactRenderRequest } from "../src/viewer/artifact-frame.js";
import { directChildren, normalizeFolderPage } from "../src/viewer/folder.js";
import { canEdit, ShareEditor } from "../src/viewer/editor.js";

const REPORT = "<!doctype html><title>Report</title><style>h1{color:rgb(1,2,3)}</style><h1 id=marker-1f3a>Q3</h1><script>document.body.dataset.ran='yes'</script>";

function frameMessage(iframe: HTMLIFrameElement, data: Record<string, unknown>): void {
  window.dispatchEvent(new MessageEvent("message", { source: iframe.contentWindow, origin: "null", data }));
}

describe("adaptive viewer adapters", () => {
  it("routes HTML only to the sandboxed page renderer and keeps SVG download-only", () => {
    expect(classifyContent({ mediaType: "text/html;charset=utf-8", filename: "page.html", byteLength: 1 })).toBe("html");
    // Bearer keys carry no signed media type; the key's extension decides.
    expect(classifyContent({ mediaType: "application/octet-stream", filename: "report.HTML", byteLength: 1 })).toBe("html");
    expect(classifyContent({ mediaType: "application/octet-stream", filename: "report.htm", byteLength: 1 })).toBe("html");
    // A signed non-HTML media type wins over a misleading extension.
    expect(classifyContent({ mediaType: "text/plain", filename: "page.html", byteLength: 1 })).toBe("text");
    expect(classifyContent({ mediaType: "application/octet-stream", filename: "notes.md", byteLength: 1 })).toBe("markdown");
    expect(classifyContent({ mediaType: "image/svg+xml", filename: "image.svg", byteLength: 1 })).toBe("download");
    expect(canEdit("text/html", ["edit"])).toBe(false);
  });

  it("hands HTML to the opaque-origin sandbox and never into the viewer DOM", async () => {
    const root = document.createElement("main");
    document.body.append(root);
    const rendered = renderSafeContent(root, new TextEncoder().encode(REPORT), { mediaType: "application/octet-stream", filename: "report.html", byteLength: 1 });
    const iframe = root.querySelector<HTMLIFrameElement>(`iframe.${HTML_FRAME_CLASS}`)!;
    expect(iframe.getAttribute("sandbox")).toBe("allow-scripts");
    expect(iframe.getAttribute("src")).toMatch(new RegExp(`^${ARTIFACT_SANDBOX_PATH}#[0-9a-f]{32}$`));
    expect(iframe.hidden).toBe(false);
    expect(root.querySelector(".viewer-html-notice")?.textContent).toContain("This page comes from the sender");
    expect(root.innerHTML).not.toContain("marker-1f3a");
    const posted: ArtifactRenderRequest[] = [];
    iframe.contentWindow!.postMessage = ((message: ArtifactRenderRequest) => { posted.push(message); }) as typeof window.postMessage;
    const nonce = iframe.getAttribute("src")!.split("#")[1]!;
    frameMessage(iframe, { type: "ready", nonce });
    expect(posted).toEqual([expect.objectContaining({ type: "render", nonce, ready: "load", entry: "index.html", pages: { "index.html": REPORT } })]);
    frameMessage(iframe, { type: "result", nonce, id: posted[0]!.id, ok: true });
    await expect(rendered).resolves.toBe("html");
    // A later navigation inside the page closes it instead of showing a foreign document.
    frameMessage(iframe, { type: "result", nonce, id: posted[0]!.id, ok: false, error: "navigation" });
    expect(root.querySelector("iframe")).toBeNull();
    expect(root.textContent).toContain("tried to open another page");
    root.remove();
  });

  it("fails closed without leaving a frame when the HTML page does not load", async () => {
    const root = document.createElement("main");
    document.body.append(root);
    const rendered = renderSafeContent(root, new TextEncoder().encode(REPORT), { mediaType: "text/html", filename: "report.html", byteLength: 1 });
    const iframe = root.querySelector<HTMLIFrameElement>("iframe")!;
    let id = "";
    iframe.contentWindow!.postMessage = ((message: ArtifactRenderRequest) => { id = message.id; }) as typeof window.postMessage;
    const nonce = iframe.getAttribute("src")!.split("#")[1]!;
    frameMessage(iframe, { type: "ready", nonce });
    frameMessage(iframe, { type: "result", nonce, id, ok: false, error: "navigation" });
    await expect(rendered).rejects.toThrow("artifact sandbox render failed");
    expect(root.childElementCount).toBe(0);
    root.remove();
  });

  it("keeps oversized and non-UTF-8 HTML download-only", async () => {
    Object.defineProperty(URL, "createObjectURL", { configurable: true, value: () => "blob:viewer-test" });
    Object.defineProperty(URL, "revokeObjectURL", { configurable: true, value: () => undefined });
    const root = document.createElement("main");
    expect(await renderSafeContent(root, new Uint8Array(MAX_SAFE_CONTENT_BYTES + 1), { mediaType: "text/html", filename: "big.html", byteLength: 1 })).toBe("download");
    expect(root.querySelector("iframe")).toBeNull();
    expect(await renderSafeContent(root, Uint8Array.from([0xff, 0xfe]), { mediaType: "text/html", filename: "bad.html", byteLength: 2 })).toBe("download");
    expect(root.querySelector("iframe")).toBeNull();
    expect(root.querySelector("a")?.textContent).toBe("Download file");
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
