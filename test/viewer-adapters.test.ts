import { describe, expect, it, vi } from "vitest";
import { classifyContent, HTML_FRAME_CLASS, MAX_SAFE_CONTENT_BYTES, renderSafeContent } from "../src/viewer/content.js";
import { ARTIFACT_SANDBOX_PATH, withLoadSignal, type ArtifactRenderRequest } from "../src/viewer/artifact-frame.js";
import { presentShare } from "../src/viewer/present.js";
import { presentationEnvelope } from "../src/viewer/resolve.js";
import { directChildren, normalizeFolderPage } from "../src/viewer/folder.js";
import { canEdit, ShareEditor } from "../src/viewer/editor.js";

const REPORT = "<!doctype html><title>Report</title><style>h1{color:rgb(1,2,3)}</style><h1 id=marker-1f3a>Q3</h1><script>document.body.dataset.ran='yes'</script>";
const PREVIEW_UNAVAILABLE = "Preview isn't available for this link type yet";

function frameMessage(iframe: HTMLIFrameElement, data: Record<string, unknown>): void {
  window.dispatchEvent(new MessageEvent("message", { source: iframe.contentWindow, origin: "null", data }));
}

/** Answer the sandbox handshake and capture the render request it sends. */
function handshake(iframe: HTMLIFrameElement): { readonly nonce: string; readonly posted: ArtifactRenderRequest[] } {
  const posted: ArtifactRenderRequest[] = [];
  iframe.contentWindow!.postMessage = ((message: ArtifactRenderRequest) => { posted.push(message); }) as typeof window.postMessage;
  const nonce = iframe.getAttribute("src")!.split("#")[1]!;
  frameMessage(iframe, { type: "ready", nonce });
  return { nonce, posted };
}

function stubObjectUrls(): void {
  Object.defineProperty(URL, "createObjectURL", { configurable: true, value: () => "blob:viewer-test" });
  Object.defineProperty(URL, "revokeObjectURL", { configurable: true, value: () => undefined });
}

function htmlShare(access: "bearer" | "policy", mediaType?: string): Parameters<typeof presentShare>[1] {
  const path = "applications/share/report.html";
  return {
    state: "ok",
    access,
    senderVerified: access === "policy",
    contentBytes: new TextEncoder().encode(REPORT),
    envelope: presentationEnvelope({
      protocol: "tinycloud-share",
      version: 1,
      shareId: path,
      origin: "https://share.tinycloud.xyz",
      target: { kind: "bearer", origin: "https://node.tinycloud.xyz", nodeAudience: "", spaceId: "space" },
      resource: { kind: "exact", path },
      actions: ["tinycloud.kv/get"],
      display: { filename: "report.html" },
      expiresAt: "2030-01-01T00:00:00.000Z",
    } as Parameters<typeof presentationEnvelope>[0], mediaType === undefined ? undefined : { filename: "report.html", mediaType }),
  };
}

describe("adaptive viewer adapters", () => {
  it("recognizes HTML by signed type or bearer key extension and keeps SVG download-only", () => {
    expect(classifyContent({ mediaType: "text/html;charset=utf-8", filename: "page.html", byteLength: 1 })).toBe("html");
    expect(classifyContent({ mediaType: "application/octet-stream", filename: "report.HTML", byteLength: 1 })).toBe("html");
    expect(classifyContent({ mediaType: "application/octet-stream", filename: "report.htm", byteLength: 1 })).toBe("html");
    // A signed non-HTML media type wins over a misleading extension.
    expect(classifyContent({ mediaType: "text/plain", filename: "page.html", byteLength: 1 })).toBe("text");
    expect(classifyContent({ mediaType: "application/octet-stream", filename: "notes.md", byteLength: 1 })).toBe("markdown");
    expect(classifyContent({ mediaType: "image/svg+xml", filename: "image.svg", byteLength: 1 })).toBe("download");
    expect(canEdit("text/html", ["edit"])).toBe(false);
  });

  it.each([
    ["an addressed link with signed text/html", "policy", "text/html"],
    ["an addressed octet-stream file named .html", "policy", "application/octet-stream"],
    ["an unknown link type", undefined, "text/html"],
  ] as const)("never executes HTML from %s", async (_label, linkAccess, mediaType) => {
    stubObjectUrls();
    const root = document.createElement("main");
    document.body.append(root);
    expect(await renderSafeContent(root, new TextEncoder().encode(REPORT), { mediaType, filename: "report.html", byteLength: 1 }, linkAccess === undefined ? {} : { linkAccess })).toBe("download");
    expect(root.querySelector("iframe")).toBeNull();
    expect(document.querySelector("iframe")).toBeNull();
    expect(root.textContent).toContain(PREVIEW_UNAVAILABLE);
    expect(root.querySelector("a")?.textContent).toBe("Download file");
    root.remove();
  });

  it("hands bearer HTML to the opaque-origin sandbox and never into the viewer DOM", async () => {
    const root = document.createElement("main");
    document.body.append(root);
    const rendered = renderSafeContent(root, new TextEncoder().encode(REPORT), { mediaType: "application/octet-stream", filename: "report.html", byteLength: 1 }, { linkAccess: "bearer" });
    const iframe = root.querySelector<HTMLIFrameElement>(`iframe.${HTML_FRAME_CLASS}`)!;
    expect(iframe.getAttribute("sandbox")).toBe("allow-scripts");
    expect(iframe.getAttribute("src")).toMatch(new RegExp(`^${ARTIFACT_SANDBOX_PATH}#[0-9a-f]{32}$`));
    expect(iframe.hidden).toBe(false);
    const notice = root.querySelector(".viewer-html-notice")?.textContent ?? "";
    expect(notice).toContain("comes from the sender");
    expect(notice).toContain("WebRTC");
    expect(root.innerHTML).not.toContain("marker-1f3a");
    const { nonce, posted } = handshake(iframe);
    expect(posted).toHaveLength(1);
    const request = posted[0]!;
    expect(request).toMatchObject({ type: "render", nonce, ready: "load", entry: "index.html" });
    expect(request.loadToken).toMatch(/^[0-9a-f]{32}$/);
    expect(request.pages["index.html"]).toBe(withLoadSignal(REPORT, request.loadToken!));
    frameMessage(iframe, { type: "result", nonce, id: request.id, ok: true });
    await expect(rendered).resolves.toBe("html");
    // A later navigation inside the page closes it instead of showing a foreign document.
    frameMessage(iframe, { type: "result", nonce, id: request.id, ok: false, error: "navigation" });
    expect(root.querySelector("iframe")).toBeNull();
    expect(root.textContent).toContain("tried to open another page");
    root.remove();
  });

  it("inserts the load signal without leaving standards mode or dropping root attributes", () => {
    const token = "0123456789abcdef0123456789abcdef";
    const signaled = withLoadSignal("<!-- generated --><!DOCTYPE html><html lang=\"fr\"><head><meta charset=\"utf-8\"><title>T</title></head><body><p>x</p></body></html>", token);
    expect(signaled.startsWith("<!-- generated --><!DOCTYPE html><script>")).toBe(true);
    const parsed = new DOMParser().parseFromString(signaled, "text/html");
    expect(parsed.compatMode).toBe("CSS1Compat");
    expect(parsed.documentElement.lang).toBe("fr");
    expect(parsed.title).toBe("T");
    expect(parsed.scripts[0]?.textContent).toContain(token);
    expect(withLoadSignal("<p>no doctype</p>", token).startsWith("<script>")).toBe(true);
  });

  it("fails closed without leaving a frame when the HTML page does not load", async () => {
    const root = document.createElement("main");
    document.body.append(root);
    const rendered = renderSafeContent(root, new TextEncoder().encode(REPORT), { mediaType: "text/html", filename: "report.html", byteLength: 1 }, { linkAccess: "bearer" });
    const iframe = root.querySelector<HTMLIFrameElement>("iframe")!;
    const { nonce, posted } = handshake(iframe);
    frameMessage(iframe, { type: "result", nonce, id: posted[0]!.id, ok: false, error: "navigation" });
    await expect(rendered).rejects.toThrow("artifact sandbox render failed");
    expect(root.childElementCount).toBe(0);
    root.remove();
  });

  it("keeps the verified-bytes download when the HTML preview fails", async () => {
    const root = document.createElement("div");
    document.body.append(root);
    const presented = presentShare(root, htmlShare("bearer"));
    await Promise.resolve();
    expect(root.querySelector(".viewer-download")?.textContent).toBe("Download original");
    const iframe = await vi.waitFor(() => root.querySelector<HTMLIFrameElement>(`iframe.${HTML_FRAME_CLASS}`)!);
    const { nonce, posted } = handshake(iframe);
    frameMessage(iframe, { type: "result", nonce, id: posted[0]!.id, ok: false, error: "navigation" });
    await presented;
    expect(root.querySelector("iframe")).toBeNull();
    expect(root.querySelector(".viewer-render-error")?.textContent).toContain("Download it to open it");
    expect(root.querySelector(".viewer-download")?.textContent).toBe("Download original");
    root.remove();
  });

  it("shows addressed HTML as download-only with the link-type note", async () => {
    stubObjectUrls();
    const root = document.createElement("div");
    document.body.append(root);
    await presentShare(root, htmlShare("policy", "text/html"));
    expect(document.querySelector("iframe")).toBeNull();
    expect(root.querySelector(".viewer-file-note")?.textContent).toContain(PREVIEW_UNAVAILABLE);
    expect(root.querySelector(".viewer-download")?.textContent).toBe("Download original");
    root.remove();
  });

  it("keeps oversized and non-UTF-8 HTML download-only", async () => {
    stubObjectUrls();
    const root = document.createElement("main");
    expect(await renderSafeContent(root, new Uint8Array(MAX_SAFE_CONTENT_BYTES + 1), { mediaType: "text/html", filename: "big.html", byteLength: 1 }, { linkAccess: "bearer" })).toBe("download");
    expect(root.querySelector("iframe")).toBeNull();
    expect(await renderSafeContent(root, Uint8Array.from([0xff, 0xfe]), { mediaType: "text/html", filename: "bad.html", byteLength: 2 }, { linkAccess: "bearer" })).toBe("download");
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
