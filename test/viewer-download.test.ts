import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { downloadMediaType, safeDownloadName } from "../src/viewer/download-name.js";
import { renderSafeContent } from "../src/viewer/content.js";
import { presentShare } from "../src/viewer/present.js";
import { presentationEnvelope } from "../src/viewer/resolve.js";

type Presentable = Parameters<typeof presentShare>[1];

/** A bearer share whose SIGNED download name may differ from the name shown in the bar. */
function share(downloadName: string | undefined, shown = "report.md", signedType = "text/markdown", access: "bearer" | "policy" = "bearer"): Presentable {
  const path = `applications/share/${shown}`;
  const envelope = presentationEnvelope({
    protocol: "tinycloud-share",
    version: 1,
    shareId: path,
    origin: "https://share.tinycloud.xyz",
    target: { kind: "bearer", origin: "https://node.tinycloud.xyz", nodeAudience: "", spaceId: "space" },
    resource: { kind: "exact", path },
    actions: ["tinycloud.kv/get"],
    display: { filename: shown },
    expiresAt: "2030-01-01T00:00:00.000Z",
  } as Parameters<typeof presentationEnvelope>[0]);
  // The signed metadata is attacker-controlled input; set it unchecked, as a hostile envelope could.
  if (downloadName !== undefined) Object.assign(envelope, { metadata: { filename: downloadName, mediaType: signedType } });
  return { state: "ok", access, senderVerified: access === "policy", contentBytes: new TextEncoder().encode("# hello"), envelope };
}

let downloads: string[];
let blobs: Blob[];
beforeEach(() => {
  downloads = [];
  blobs = [];
  document.body.innerHTML = '<div id="viewer"></div>';
  localStorage.clear();
  Object.defineProperty(URL, "createObjectURL", { configurable: true, value: (blob: Blob) => { blobs.push(blob); return "blob:viewer-test"; } });
  Object.defineProperty(URL, "revokeObjectURL", { configurable: true, value: () => undefined });
  vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(function click(this: HTMLAnchorElement) { downloads.push(this.download); });
});
afterEach(() => vi.restoreAllMocks());

describe("Download names", () => {
  const present = async (downloadName: string | undefined, shown?: string): Promise<HTMLButtonElement | null> => {
    const root = document.getElementById("viewer")!;
    await presentShare(root, share(downloadName, shown));
    return root.querySelector<HTMLButtonElement>("button.viewer-download");
  };

  it.each([
    ["a path separator", "dir/report.md"],
    ["a backslash", "dir\\report.md"],
    ["a parent reference", ".."],
    ["a right-to-left override", "report\u202Etxt.md"],
    ["a bidi isolate", "report\u2066.md"],
    ["a control character", "report\u0000.md"],
    ["a line separator", "report\u2028.md"],
  ])("offers no download when the signed name holds %s", async (_label, name) => {
    expect(await present(name)).toBeNull();
    expect(downloads).toEqual([]);
  });

  it("keeps a name whose final extension the viewer knows for this kind", async () => {
    for (const name of ["report.md", "q3 report (final).md", "notes.markdown", "REPORT.MD", "a.b.c.md"]) {
      document.body.innerHTML = '<div id="viewer"></div>';
      const button = await present(name);
      expect(button, name).not.toBeNull();
      button!.click();
      await vi.waitFor(() => expect(downloads.at(-1)).toBe(name));
    }
  });

  it("appends the kind's extension instead of passing a double extension through", async () => {
    for (const [name, saved] of [["report.md.exe", "report.md.exe.md"], ["a.pdf", "a.pdf.md"], ["archive.tar.gz", "archive.tar.gz.md"]] as const) {
      document.body.innerHTML = '<div id="viewer"></div>';
      (await present(name))!.click();
      await vi.waitFor(() => expect(downloads.at(-1)).toBe(saved));
    }
  });

  it("types the saved copy from the kind, and names it for the kind, whatever the sender signed", async () => {
    const root = document.getElementById("viewer")!;
    // A page the viewer does not run (addressed link): download-only. The signed type says HTML.
    await presentShare(root, share("report.md", "report.md", "text/html", "policy"));
    root.querySelector<HTMLButtonElement>("button.viewer-download")!.click();
    await vi.waitFor(() => expect(downloads).toEqual(["report.md.html"]));
    expect(blobs.at(-1)!.type).toBe("application/octet-stream");

    document.body.innerHTML = '<div id="viewer"></div>';
    await presentShare(document.getElementById("viewer")!, share("report.md", "report.md", "text/markdown"));
    document.querySelector<HTMLButtonElement>("button.viewer-download")!.click();
    await vi.waitFor(() => expect(blobs.at(-1)!.type).toBe("text/markdown;charset=utf-8"));
    expect(downloads.at(-1)).toBe("report.md");
  });

  it("applies the same name to the in-page Download file link", async () => {
    const root = document.createElement("main");
    document.body.append(root);
    await renderSafeContent(root, new Uint8Array([1, 2, 3]), { mediaType: "application/octet-stream", filename: "tool.md.exe", byteLength: 3 });
    expect(root.querySelector("a")?.download).toBe("tool.md.exe.bin");
  });

  it("normalises the signed name to NFC", async () => {
    const button = await present("re\u0301sume\u0301.md");
    button!.click();
    await vi.waitFor(() => expect(downloads).toEqual(["r\u00e9sum\u00e9.md"]));
  });

  it("falls back to the shown file name when nothing was signed", async () => {
    const button = await present(undefined, "notes.md");
    button!.click();
    await vi.waitFor(() => expect(downloads).toEqual(["notes.md"]));
  });
});

describe("safeDownloadName", () => {
  it.each([
    ["markdown", "a.md.exe", "a.md.exe.md"],
    ["html", "a.html.js", "a.html.js.html"],
    ["markdown", ".bashrc", "bashrc.md"],
    ["markdown", "a.", "a.md"],
    ["markdown", "a..md", "a.md"],
    ["markdown", "...", "artifact.md"],
    ["markdown", "", "artifact.md"],
    ["html", "", "artifact.html"],
    ["text", "", "artifact.txt"],
    ["file", "", "artifact.bin"],
    ["markdown", "résumé 日本語.md", "résumé 日本語.md"],
    ["markdown", "📄 notes.md", "📄 notes.md"],
    ["markdown", "page.html", "page.html.md"],
    ["html", "page.htm", "page.htm"],
    ["html", "page.md", "page.md.html"],
    ["text", "data.csv", "data.csv"],
    ["text", "data.md", "data.md.txt"],
    ["file", "tool.exe", "tool.exe.bin"],
    ["file", "scan.pdf", "scan.pdf"],
    ["download", "x.svg", "x.svg.bin"],
    ["markdown", "no extension", "no extension.md"],
    ["markdown", "trailing dots...", "trailing dots.md"],
  ] as const)("%s: %j -> %j", (kind, name, saved) => {
    expect(safeDownloadName(name, kind)).toBe(saved);
  });

  it("never keeps a final extension that can run or install, in any case, for any kind", () => {
    for (const extension of ["exe", "bat", "cmd", "com", "scr", "msi", "ps1", "vbs", "js", "jar", "sh", "app", "dmg", "lnk", "hta", "apk", "EXE", "Js", "PS1"]) {
      for (const kind of ["markdown", "html", "text", "image", "file", "download"] as const) {
        const saved = safeDownloadName(`a.${extension}`, kind);
        expect(saved.toLowerCase().endsWith(`.${extension.toLowerCase()}`), `${kind} ${extension} -> ${saved}`).toBe(false);
        expect(saved.startsWith(`a.${extension}.`)).toBe(true);
      }
    }
  });

  it("truncates to 120 characters, keeping the extension and never splitting a character", () => {
    const long = safeDownloadName(`${"x".repeat(300)}.md`, "markdown");
    expect(Array.from(long)).toHaveLength(120);
    expect(long.endsWith(".md")).toBe(true);
    const appended = safeDownloadName(`${"x".repeat(300)}.exe`, "markdown");
    expect(Array.from(appended).length).toBeLessThanOrEqual(120);
    expect(appended.endsWith(".md")).toBe(true);
    const emoji = safeDownloadName(`${"📄".repeat(200)}.md`, "markdown");
    expect(Array.from(emoji)).toHaveLength(120);
    expect(emoji.endsWith(".md")).toBe(true);
    expect(emoji).not.toMatch(/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/);
    expect(safeDownloadName(`${"x".repeat(119)}. .md`, "markdown").endsWith(".md")).toBe(true);
  });

  it("derives an image extension from the signed type and refuses unsafe names like the share policy", () => {
    expect(safeDownloadName("photo.exe", "image", "image/jpeg")).toBe("photo.exe.jpg");
    expect(safeDownloadName("photo.png", "image", "image/png")).toBe("photo.png");
    expect(safeDownloadName("photo", "image", "image/webp")).toBe("photo.webp");
    for (const bad of ["a/b.md", "a\\b.md", ".", "..", "a\u202Eb.md", "a\u0000.md"]) expect(() => safeDownloadName(bad, "markdown"), bad).toThrow();
  });

  it("forces the Blob type from the kind, never from the sender", () => {
    expect(downloadMediaType("markdown")).toBe("text/markdown;charset=utf-8");
    expect(downloadMediaType("text")).toBe("text/plain;charset=utf-8");
    for (const kind of ["html", "file", "download", "image"] as const) expect(downloadMediaType(kind)).toBe("application/octet-stream");
  });
});
