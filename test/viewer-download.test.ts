import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { presentShare } from "../src/viewer/present.js";
import { presentationEnvelope } from "../src/viewer/resolve.js";

type Presentable = Parameters<typeof presentShare>[1];

/** A bearer share whose SIGNED download name may differ from the name shown in the bar. */
function share(downloadName: string | undefined, shown = "report.md"): Presentable {
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
  if (downloadName !== undefined) Object.assign(envelope, { metadata: { filename: downloadName, mediaType: "text/markdown" } });
  return { state: "ok", access: "bearer", senderVerified: false, contentBytes: new TextEncoder().encode("# hello"), envelope };
}

let downloads: string[];
beforeEach(() => {
  downloads = [];
  document.body.innerHTML = '<div id="viewer"></div>';
  localStorage.clear();
  Object.defineProperty(URL, "createObjectURL", { configurable: true, value: () => "blob:viewer-test" });
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

  it("saves under the exact safe name the sender signed, and never rewrites extensions", async () => {
    for (const name of ["report.md", "q3 report (final).md", "archive.tar.gz", "report.md.exe"]) {
      document.body.innerHTML = '<div id="viewer"></div>';
      const button = await present(name);
      expect(button, name).not.toBeNull();
      button!.click();
      await vi.waitFor(() => expect(downloads.at(-1)).toBe(name.normalize("NFC")));
    }
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
