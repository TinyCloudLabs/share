import { createHash } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { presentShare } from "../src/viewer/present.js";
import { presentationEnvelope } from "../src/viewer/resolve.js";
import { SAVE_APPROVAL_HINT, SaveCopyError, type SavedCopyInput, type SaveProgress, type SaveToTinyCloud } from "../src/viewer/save-copy.js";

type Presentable = Parameters<typeof presentShare>[1];

/** `signedName` is the attacker-controlled signed filename, which may differ from the name shown in the bar. */
function share(filename: string, bytes: Uint8Array, signedType?: string, signedName: string = filename): Presentable {
  const path = `applications/share/${filename}`;
  const envelope = presentationEnvelope({
    protocol: "tinycloud-share",
    version: 1,
    shareId: path,
    origin: "https://share.tinycloud.xyz",
    target: { kind: "bearer", origin: "https://node.tinycloud.xyz", nodeAudience: "", spaceId: "space" },
    resource: { kind: "exact", path },
    actions: ["tinycloud.kv/get"],
    display: { filename },
    expiresAt: "2030-01-01T00:00:00.000Z",
  } as Parameters<typeof presentationEnvelope>[0]);
  if (signedType !== undefined) Object.assign(envelope, { metadata: { filename: signedName, mediaType: signedType } });
  return { state: "ok", access: "bearer", senderVerified: false, contentBytes: bytes, envelope };
}

const sha256 = (bytes: Uint8Array): string => createHash("sha256").update(bytes).digest("hex");
const MARKDOWN = new TextEncoder().encode("# Quarterly notes\n\nA table:\n\n| a | b |\n|---|---|\n| 1 | 2 |\n");

let root: HTMLElement;
beforeEach(() => {
  document.body.innerHTML = '<div id="viewer"></div>';
  localStorage.clear();
  root = document.getElementById("viewer")!;
});
afterEach(() => vi.restoreAllMocks());

const saveButton = (): HTMLButtonElement | null => root.querySelector<HTMLButtonElement>("button.viewer-save-to-tinycloud");
/** The save's own live region: pending, approval, done, failure. */
const toast = (): HTMLElement => root.querySelector<HTMLElement>(".artifact-chrome-toast--job")!;
/** The Copy / Download result, which fades. */
const copyToast = (): HTMLElement => root.querySelector<HTMLElement>(".artifact-chrome-toast:not(.artifact-chrome-toast--job)")!;

/** A save the test settles by hand, so each state of the bar can be looked at. */
function pendingSave(): { save: SaveToTinyCloud; calls: SavedCopyInput[]; progress: () => SaveProgress; resolve: (name?: string) => void; reject: (error: unknown) => void } {
  const calls: SavedCopyInput[] = [];
  let progress: SaveProgress | undefined;
  let resolve!: (name?: string) => void;
  let reject!: (error: unknown) => void;
  const save: SaveToTinyCloud = (copy, reported) => {
    calls.push(copy);
    progress = reported;
    return new Promise((done, fail) => { resolve = (name = "report.md") => done({ path: `files-for-you/v1/${encodeURIComponent(name)}`, name }); reject = fail; });
  };
  return { save, calls, progress: () => progress!, resolve: (name) => resolve(name), reject: (error) => reject(error) };
}

describe("Save a copy in the bar", () => {
  it("sits next to Copy link, Download and Hide for a document, and starts nothing before a click", async () => {
    const save = vi.fn<SaveToTinyCloud>(async () => ({ path: "files-for-you/v1/report.md", name: "report.md" }));
    await presentShare(root, share("report.md", MARKDOWN), { shareUrl: "https://share.tinycloud.xyz/viewer#tc1=x", saveToTinyCloud: save });

    const labels = [...root.querySelectorAll(".artifact-chrome-actions .artifact-chrome-label")].map((node) => node.textContent);
    expect(labels).toEqual(["Copy link", "Copy text", "Download", "Save a copy", "Share on", "Hide"]);
    expect(save).not.toHaveBeenCalled();
  });

  it.each([
    ["page.html", "<!doctype html><title>t</title><p>hi</p>"],
    ["card.jsx", "export default function Card() { return <p>hi</p>; }"],
  ])("offers it for %s too", async (name, source) => {
    // A page or a component renders in a sandbox frame that never answers in jsdom; the bar is up before that.
    void presentShare(root, share(name, new TextEncoder().encode(source)), { saveToTinyCloud: vi.fn<SaveToTinyCloud>() }).catch(() => undefined);
    await vi.waitFor(() => expect(saveButton()).not.toBeNull());
  });

  it.each([
    ["plain text", "notes.txt", new TextEncoder().encode("just text")],
    ["an image", "photo.png", Uint8Array.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])],
    ["an opaque file", "blob.bin", Uint8Array.from([0, 0x80, 0xff, 0x0a])],
  ])("is not offered for %s", async (_label, name, bytes) => {
    await presentShare(root, share(name, bytes), { saveToTinyCloud: vi.fn<SaveToTinyCloud>() });
    expect(saveButton()).toBeNull();
  });

  it("is not offered when the page was given no way to save", async () => {
    await presentShare(root, share("report.md", MARKDOWN));
    expect(saveButton()).toBeNull();
  });

  it("is not offered for a name the download policy refuses", async () => {
    await presentShare(root, share("report.md", MARKDOWN, "text/markdown", "dir/report.md"), { saveToTinyCloud: vi.fn<SaveToTinyCloud>() });
    expect(saveButton()).toBeNull();
  });

  it("hands over exactly the received bytes, under the safe name, with a media type for the kind", async () => {
    const save = vi.fn<SaveToTinyCloud>(async () => ({ path: "files-for-you/v1/report.md", name: "report.md" }));
    await presentShare(root, share("report.md", MARKDOWN), { saveToTinyCloud: save });
    saveButton()!.click();
    await vi.waitFor(() => expect(save).toHaveBeenCalledTimes(1));
    const [copy] = save.mock.calls[0]!;
    expect(copy.bytes).toBe(MARKDOWN);
    expect(sha256(copy.bytes)).toBe(sha256(MARKDOWN));
    expect(copy.filename).toBe("report.md");
    expect(copy.mediaType).toBe("text/markdown;charset=utf-8");
  });

  it("saves a page or a component as its source text, never typed as a page, whatever the sender signed", async () => {
    const source = new TextEncoder().encode("<!doctype html><title>t</title><script>alert(1)</script>");
    const save = vi.fn<SaveToTinyCloud>(async () => ({ path: "files-for-you/v1/page.html", name: "page.html" }));
    void presentShare(root, share("page.html", source, "text/html"), { saveToTinyCloud: save }).catch(() => undefined);
    await vi.waitFor(() => expect(saveButton()).not.toBeNull());
    saveButton()!.click();
    await vi.waitFor(() => expect(save).toHaveBeenCalledTimes(1));
    const [copy] = save.mock.calls[0]!;
    expect(sha256(copy.bytes)).toBe(sha256(source));
    expect(copy.filename).toBe("page.html");
    expect(copy.mediaType).toBe("text/plain;charset=utf-8");
  });

  it("does not trust a signed name that claims another type", async () => {
    const save = vi.fn<SaveToTinyCloud>(async () => ({ path: "files-for-you/v1/report.md.exe.md", name: "report.md.exe.md" }));
    await presentShare(root, share("report.md.exe", MARKDOWN, "text/markdown"), { saveToTinyCloud: save });
    saveButton()!.click();
    await vi.waitFor(() => expect(save).toHaveBeenCalledTimes(1));
    expect(save.mock.calls[0]![0].filename).toBe("report.md.exe.md");
  });
});

describe("Save a copy: pending, approval, saved", () => {
  it("shows pending, asks for the OpenKey approval out loud, and runs once however often it is clicked", async () => {
    const pending = pendingSave();
    await presentShare(root, share("report.md", MARKDOWN), { saveToTinyCloud: pending.save });
    const button = saveButton()!;
    expect(button.getAttribute("aria-disabled")).toBeNull();

    button.click();
    button.click();
    button.click();
    await vi.waitFor(() => expect(pending.calls).toHaveLength(1));
    expect(button.getAttribute("aria-busy")).not.toBeNull();
    expect(button.getAttribute("aria-disabled")).toBe("true");
    expect(button.querySelector(".artifact-chrome-label")?.textContent).toBe("Saving…");
    expect(toast().getAttribute("role")).toBe("status");
    expect(toast().textContent).toBe("Saving a copy to your TinyCloud…");

    pending.progress().approval(true);
    expect(toast().textContent).toBe(SAVE_APPROVAL_HINT);
    expect(toast().getAttribute("aria-live")).toBe("polite");
    pending.progress().approval(false);
    expect(toast().textContent).toBe("Saving a copy to your TinyCloud…");

    pending.resolve();
    await vi.waitFor(() => expect(button.querySelector(".artifact-chrome-label")?.textContent).toBe("Saved"));
    expect(pending.calls).toHaveLength(1);
  });

  it("counts the approvals when the save says which one is open: the same words each time, with 'Approval n of up to 4' in front", async () => {
    const pending = pendingSave();
    await presentShare(root, share("report.md", MARKDOWN), { saveToTinyCloud: pending.save });
    saveButton()!.click();
    await vi.waitFor(() => expect(pending.calls).toHaveLength(1));
    for (const n of [1, 2, 3, 4]) {
      pending.progress().approval(true, { n, of: 4 });
      expect(toast().textContent).toBe(`Approval ${n} of up to 4. ${SAVE_APPROVAL_HINT}`);
      expect(toast().getAttribute("aria-live")).toBe("polite");
      pending.progress().approval(false);
      expect(toast().textContent).toBe("Saving a copy to your TinyCloud…");
    }
    // Opening OpenKey is not a signature: no count.
    pending.progress().approval(true);
    expect(toast().textContent).toBe(SAVE_APPROVAL_HINT);
  });

  it("announces what was saved and where, as plain text with no link, and keeps saying it", async () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    try {
      const pending = pendingSave();
      await presentShare(root, share("report.md", MARKDOWN), { saveToTinyCloud: pending.save });
      const button = saveButton()!;
      button.click();
      await vi.waitFor(() => expect(pending.calls).toHaveLength(1));
      pending.resolve("report.md");
      await vi.waitFor(() => expect(button.getAttribute("aria-busy")).toBeNull());

      expect(toast().getAttribute("role")).toBe("status");
      expect(toast().getAttribute("aria-live")).toBe("polite");
      expect(toast().textContent).toBe("Saved to your TinyCloud files as “report.md”.");
      // The library lists shares, not saved copies, so there is nothing to link to.
      expect(toast().querySelector("a")).toBeNull();
      expect(root.querySelector(".artifact-chrome-toasts a")).toBeNull();

      vi.advanceTimersByTime(60_000);
      expect(toast().textContent).toBe("Saved to your TinyCloud files as “report.md”.");
      // Done is final: another click does not save again.
      button.click();
      expect(pending.calls).toHaveLength(1);
    } finally {
      vi.useRealTimers();
    }
  });

  it("shows the name the copy really got, decoded and as text, so a clash is noticed", async () => {
    const pending = pendingSave();
    await presentShare(root, share("report.md", MARKDOWN), { saveToTinyCloud: pending.save });
    saveButton()!.click();
    await vi.waitFor(() => expect(pending.calls).toHaveLength(1));
    pending.resolve("q3 report (2) <b>é</b>.md");
    await vi.waitFor(() => expect(toast().textContent).toContain("(2)"));
    expect(toast().textContent).toBe("Saved to your TinyCloud files as “q3 report (2) <b>é</b>.md”.");
    expect(toast().querySelector("b")).toBeNull();
  });

  it("a later Copy link does not replace the lasting Saved message, and its own result still shows", async () => {
    const pending = pendingSave();
    await presentShare(root, share("report.md", MARKDOWN), { shareUrl: "https://share.tinycloud.xyz/viewer#tc1=x", saveToTinyCloud: pending.save });
    Object.assign(navigator, { clipboard: { writeText: vi.fn(async () => undefined) } });
    saveButton()!.click();
    await vi.waitFor(() => expect(pending.calls).toHaveLength(1));
    pending.resolve("report.md");
    await vi.waitFor(() => expect(toast().textContent).toContain("Saved to your TinyCloud files"));

    root.querySelector<HTMLButtonElement>(".artifact-chrome-button")!.click();
    await vi.waitFor(() => expect(copyToast().textContent).toBe("Link copied"));
    expect(toast().textContent).toBe("Saved to your TinyCloud files as “report.md”.");
    // Two regions, so neither is announced in place of the other.
    expect(toast()).not.toBe(copyToast());
    expect(toast().getAttribute("aria-live")).toBe("polite");
    expect(copyToast().getAttribute("aria-live")).toBe("polite");
  });

  it("keeps the Save button focusable while it works and after it is saved", async () => {
    const pending = pendingSave();
    await presentShare(root, share("report.md", MARKDOWN), { saveToTinyCloud: pending.save });
    const button = saveButton()!;
    button.focus();
    button.click();
    await vi.waitFor(() => expect(pending.calls).toHaveLength(1));
    expect(button.disabled).toBe(false);
    expect(document.activeElement).toBe(button);
  });
});

describe("Save a copy: a failed or cancelled sign-in is a plain message and the viewer stays usable", () => {
  it.each([
    ["cancelled", "Sign-in cancelled. Nothing was saved.", "status"],
    ["timeout", "OpenKey didn't answer in time. Nothing was saved. Try again.", "status"],
    ["busy", "Another OpenKey request is waiting. Finish or cancel it, then try again.", "status"],
    ["wrong-account", "That approval came from a different account than the one signed in. Nothing was saved.", "alert"],
    ["failed", "We couldn't save a copy. Nothing was saved. Try again.", "alert"],
  ] as const)("%s", async (reason, message, role) => {
    const pending = pendingSave();
    await presentShare(root, share("report.md", MARKDOWN), { saveToTinyCloud: pending.save });
    const button = saveButton()!;
    button.click();
    await vi.waitFor(() => expect(pending.calls).toHaveLength(1));
    pending.reject(new SaveCopyError(reason, { cause: new Error("secret-marker-9f3") }));

    await vi.waitFor(() => expect(toast().textContent).toBe(message));
    expect(toast().getAttribute("role")).toBe(role);
    // Nothing from the underlying error reaches the page.
    expect(root.textContent).not.toContain("secret-marker-9f3");
    // The button is back, and so is everything else on the bar.
    expect(button.getAttribute("aria-disabled")).toBe("false");
    expect(button.querySelector(".artifact-chrome-label")?.textContent).toBe("Save a copy");
    expect(root.querySelector("button.viewer-download")).not.toBeNull();
  });

  it("a rejection that is not one of ours is the generic message, and a retry can succeed", async () => {
    const save = vi.fn<SaveToTinyCloud>()
      .mockRejectedValueOnce(new Error("[object Object]"))
      .mockResolvedValueOnce({ path: "files-for-you/v1/report.md", name: "report.md" });
    await presentShare(root, share("report.md", MARKDOWN), { saveToTinyCloud: save });
    const button = saveButton()!;
    button.click();
    await vi.waitFor(() => expect(toast().textContent).toBe("We couldn't save a copy. Nothing was saved. Try again."));
    button.click();
    await vi.waitFor(() => expect(toast().textContent).toBe("Saved to your TinyCloud files as “report.md”."));
    expect(save).toHaveBeenCalledTimes(2);
  });

  it("a save that settles after the next share replaced the page writes nothing into it", async () => {
    const pending = pendingSave();
    await presentShare(root, share("report.md", MARKDOWN), { saveToTinyCloud: pending.save });
    saveButton()!.click();
    await vi.waitFor(() => expect(pending.calls).toHaveLength(1));
    await presentShare(root, share("other.md", MARKDOWN));
    pending.resolve();
    await Promise.resolve();
    expect(root.textContent).not.toContain("Saved to your TinyCloud");
  });
});

describe("Nothing but the person's own click on the button can start Save", () => {
  const MESSAGES: readonly unknown[] = [
    { type: "tc-save" }, { type: "save" }, { type: "saveToTinyCloud" }, { type: "tinycloud:save" }, { type: "viewer:save" },
    { type: "artifact:save" }, { type: "tinycloud-artifact", action: "save" }, { action: "save-copy" }, { kind: "save", nonce: "n" },
    { type: "openkey:auth:response", success: true, address: "0x0000000000000000000000000000000000000001" },
    { type: "openkey:ready" }, { type: "openkey:sign:response", success: true, signature: "0x00" },
    "save", "tc-save", "click", 1, null, [], { type: "click", target: ".viewer-save-to-tinycloud" },
  ];

  it("ignores every message posted to the page, from this window, a frame or nowhere", async () => {
    const save = vi.fn<SaveToTinyCloud>();
    await presentShare(root, share("report.md", MARKDOWN), { saveToTinyCloud: save });
    const frame = root.querySelector("iframe");
    const sources: (Window | null)[] = [window, frame?.contentWindow ?? null, null];
    for (const data of MESSAGES) {
      for (const source of sources) {
        for (const origin of ["", "null", "https://openkey.so", "https://share.tinycloud.xyz", "https://evil.example"]) {
          window.dispatchEvent(new MessageEvent("message", { data, origin, source }));
        }
      }
      window.postMessage(data, "*");
    }
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(save).not.toHaveBeenCalled();
    expect(saveButton()!.getAttribute("aria-busy")).toBeNull();
  });

  it("ignores keys, custom events and other clicks on the bar", async () => {
    const save = vi.fn<SaveToTinyCloud>();
    await presentShare(root, share("report.md", MARKDOWN), { saveToTinyCloud: save });
    for (const init of [{ key: "s" }, { key: "Enter" }, { key: "c", altKey: true, shiftKey: true }, { key: "s", ctrlKey: true }, { key: "s", metaKey: true }]) {
      window.dispatchEvent(new KeyboardEvent("keydown", init));
      document.body.dispatchEvent(new KeyboardEvent("keydown", { ...init, bubbles: true }));
    }
    for (const type of ["tc-save", "save", "tinycloud:save", "submit"]) {
      window.dispatchEvent(new CustomEvent(type, { detail: { save: true } }));
      root.dispatchEvent(new CustomEvent(type, { bubbles: true }));
    }
    root.querySelector<HTMLElement>(".artifact-chrome")!.click();
    root.querySelector<HTMLButtonElement>(".viewer-download")?.click();
    root.querySelector<HTMLButtonElement>(".artifact-chrome-hide")!.click();
    root.querySelector<HTMLButtonElement>(".artifact-chrome-pill")!.click();
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(save).not.toHaveBeenCalled();
  });
});
