import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { mountArtifactChrome } from "../src/viewer/artifact-chrome.js";
import { presentShare } from "../src/viewer/present.js";
import { presentationEnvelope } from "../src/viewer/resolve.js";

const FAKE_LINK = "https://share.tinycloud.xyz/viewer#tc1=FAKE-LINK-SECRET-1f2e";

beforeEach(() => {
  document.body.innerHTML = '<div id="viewer"></div>';
  localStorage.clear();
});
afterEach(() => vi.restoreAllMocks());

describe("the bar has no message channel at all", () => {
  it("registers no `message` listener on any target while it mounts, runs actions or hides and shows", async () => {
    const registered: string[] = [];
    // The window, the document and every element each have their own route to addEventListener.
    for (const target of [window, document, document.body, EventTarget.prototype] as EventTarget[]) {
      const original = target.addEventListener;
      vi.spyOn(target, "addEventListener").mockImplementation(function addEventListener(this: EventTarget, type: string, ...rest: unknown[]) {
        registered.push(type);
        return (original as (...args: unknown[]) => void).call(this, type, ...rest);
      });
    }
    const chrome = await mountArtifactChrome(document, {
      shareId: "share-no-message",
      title: "report.md",
      actions: [{ label: "Copy link", icon: "link", doneMessage: "Link copied", run: () => undefined }, { label: "Share on", icon: "share", disabledReason: "no" }],
    });
    document.querySelector<HTMLButtonElement>(".artifact-chrome-button")!.click();
    document.querySelector<HTMLButtonElement>(".artifact-chrome-hide")!.click();
    document.querySelector<HTMLButtonElement>(".artifact-chrome-pill")!.click();
    expect(registered.length).toBeGreaterThan(0);
    expect(registered.filter((type) => type.toLowerCase().includes("message"))).toEqual([]);
    chrome.destroy();
  });
});

describe("Copy link refusing never leaks the link into the page", () => {
  it("shows a message without the link, and the link is in no element, attribute or live region", async () => {
    Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText: () => Promise.reject(new DOMException("denied", "NotAllowedError")) } });
    Object.defineProperty(document, "execCommand", { configurable: true, value: () => false });
    const root = document.getElementById("viewer")!;
    const path = "applications/share/report.md";
    await presentShare(root, {
      state: "ok",
      access: "bearer",
      senderVerified: false,
      contentBytes: new TextEncoder().encode("# hello"),
      envelope: presentationEnvelope({
        protocol: "tinycloud-share",
        version: 1,
        shareId: path,
        origin: "https://share.tinycloud.xyz",
        target: { kind: "bearer", origin: "https://node.tinycloud.xyz", nodeAudience: "", spaceId: "space" },
        resource: { kind: "exact", path },
        actions: ["tinycloud.kv/get"],
        display: { filename: "report.md" },
        expiresAt: "2030-01-01T00:00:00.000Z",
      } as Parameters<typeof presentationEnvelope>[0]),
    }, { shareUrl: FAKE_LINK });

    const copy = document.querySelector<HTMLButtonElement>(".artifact-chrome-button")!;
    expect(copy.textContent).toContain("Copy link");
    copy.click();
    const toast = document.querySelector<HTMLElement>(".artifact-chrome-toast")!;
    await vi.waitFor(() => expect(toast.getAttribute("role")).toBe("alert"));
    expect(toast.textContent).toBe("Couldn't copy the link. Allow clipboard access and try again.");

    for (const [name, text] of Object.entries({
      toast: toast.textContent ?? "",
      "live region": document.querySelector(".artifact-chrome-status")?.textContent ?? "",
      "button title": copy.title,
      "button description": document.getElementById(copy.getAttribute("aria-describedby") ?? "")?.textContent ?? "",
      "whole document": document.documentElement.outerHTML,
      "document title": document.title,
      "history state": JSON.stringify(history.state),
      storage: JSON.stringify({ ...localStorage, ...sessionStorage }),
    })) {
      expect(text, name).not.toContain("FAKE-LINK-SECRET");
      expect(text, name).not.toContain("tc1=");
    }
  });
});
