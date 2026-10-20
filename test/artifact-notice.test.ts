import { beforeEach, describe, expect, it } from "vitest";

import { ARTIFACT_NOTICE_TEXT, createArtifactNotice } from "../src/viewer/artifact-notice.js";

class MemoryStorage {
  readonly values = new Map<string, string>();
  getItem(key: string): string | null { return this.values.get(key) ?? null; }
  setItem(key: string, value: string): void { this.values.set(key, value); }
}

const click = (element: HTMLElement): void => element.click();
const flush = async (): Promise<void> => { await new Promise((resolve) => setTimeout(resolve, 20)); };

describe("artifact notice", () => {
  beforeEach(() => { document.body.replaceChildren(); });

  it("says exactly one plain sentence pair and is open on first view", () => {
    const notice = createArtifactNotice(document, { storage: new MemoryStorage() });
    document.body.append(notice.element);
    expect(ARTIFACT_NOTICE_TEXT).toBe("This page runs the sender's code. The sender can tell that you opened it.");
    expect(notice.element.querySelector<HTMLElement>(".viewer-artifact-notice-text")!.textContent).toBe(ARTIFACT_NOTICE_TEXT);
    expect(notice.element.dataset["state"]).toBe("open");
    expect(notice.element.querySelector<HTMLElement>(".viewer-artifact-notice-text")!.hidden).toBe(false);
  });

  it("is dismissed only by a click on its button, stays reachable, and is remembered per share", async () => {
    const storage = new MemoryStorage();
    const notice = createArtifactNotice(document, { shareId: "share-a", storage });
    document.body.append(notice.element);
    const dismiss = notice.element.querySelector<HTMLButtonElement>(".viewer-artifact-notice-dismiss")!;
    // Nothing a frame can post reaches the dismiss path.
    for (const data of [{ v: 1, type: "dismiss" }, { type: "restore-controls" }, "dismiss"]) window.dispatchEvent(new MessageEvent("message", { source: window, origin: "null", data }));
    expect(notice.element.dataset["state"]).toBe("open");
    click(dismiss);
    expect(notice.element.dataset["state"]).toBe("collapsed");
    const recall = notice.element.querySelector<HTMLButtonElement>(".viewer-artifact-notice-recall")!;
    expect(recall.hidden).toBe(false);
    expect(document.activeElement).toBe(recall);
    click(recall);
    expect(notice.element.dataset["state"]).toBe("open");

    click(notice.element.querySelector(".viewer-artifact-notice-dismiss")!);
    await flush();
    const sameShare = createArtifactNotice(document, { shareId: "share-a", storage });
    const otherShare = createArtifactNotice(document, { shareId: "share-b", storage });
    await flush();
    expect(sameShare.element.dataset["state"]).toBe("collapsed");
    expect(otherShare.element.dataset["state"]).toBe("open");
  });

  it("stores only a digest of the share id, never the id", async () => {
    const storage = new MemoryStorage();
    const notice = createArtifactNotice(document, { shareId: "share-secret-id", storage });
    document.body.append(notice.element);
    click(notice.element.querySelector(".viewer-artifact-notice-dismiss")!);
    await flush();
    expect(storage.values.size).toBe(1);
    const [key, value] = [...storage.values][0]!;
    expect(value).toBe("1");
    expect(key).toMatch(/^tc\.artifact-notice\.v1:[0-9a-f]{64}$/);
    expect(key).not.toContain("share-secret-id");
  });

  it("reveal() shows the notice and focuses the notice itself, never a button", () => {
    const notice = createArtifactNotice(document, { shareId: "share-c", storage: new MemoryStorage() });
    document.body.append(notice.element);
    click(notice.element.querySelector(".viewer-artifact-notice-dismiss")!);
    (document.activeElement as HTMLElement | null)?.blur();
    notice.reveal();
    expect(notice.element.dataset["state"]).toBe("open");
    expect(document.activeElement).toBe(notice.element);
    expect(notice.element.tabIndex).toBe(-1);
    expect(document.activeElement?.tagName).not.toBe("BUTTON");
    notice.reveal();
    expect(notice.element.dataset["state"]).toBe("open");
  });

  it("reveal() leaves focus alone when a chrome control has it, and focus from a frame lands on the notice", () => {
    const notice = createArtifactNotice(document, { storage: new MemoryStorage() });
    const other = document.createElement("button");
    const frame = document.createElement("iframe");
    document.body.append(other, notice.element, frame);
    other.focus();
    notice.reveal();
    expect(document.activeElement).toBe(other);
    frame.focus();
    expect(document.activeElement).toBe(frame);
    notice.reveal();
    expect(document.activeElement).toBe(notice.element);
  });

  it("survives unavailable storage", async () => {
    const broken = { getItem: () => { throw new DOMException("denied", "SecurityError"); }, setItem: () => { throw new DOMException("denied", "SecurityError"); } };
    const notice = createArtifactNotice(document, { shareId: "x", storage: broken });
    document.body.append(notice.element);
    click(notice.element.querySelector(".viewer-artifact-notice-dismiss")!);
    await flush();
    expect(notice.element.dataset["state"]).toBe("collapsed");
  });
});
