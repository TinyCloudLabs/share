import { beforeEach, describe, expect, it } from "vitest";

import { ARTIFACT_NOTICE_TEXT, createArtifactNotice } from "../src/viewer/artifact-notice.js";

class MemoryStorage {
  readonly values = new Map<string, string>();
  getItem(key: string): string | null { return this.values.get(key) ?? null; }
  setItem(key: string, value: string): void { this.values.set(key, value); }
}

const click = (element: HTMLElement): void => element.click();

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

  it("is dismissed only by a click on its button, stays reachable, and is remembered per share", () => {
    const storage = new MemoryStorage();
    const notice = createArtifactNotice(document, { shareId: "share-a", storage });
    document.body.append(notice.element);
    const dismiss = notice.element.querySelector<HTMLButtonElement>(".viewer-artifact-notice-dismiss")!;
    // Nothing a frame can post reaches the dismiss path; only reveal() (restore-controls) does, and it never hides.
    for (const data of [{ v: 1, type: "dismiss" }, { type: "restore-controls" }, "dismiss"]) window.dispatchEvent(new MessageEvent("message", { source: window, origin: "null", data }));
    expect(notice.element.dataset["state"]).toBe("open");
    click(dismiss);
    expect(notice.element.dataset["state"]).toBe("collapsed");
    // Still reachable: a focusable control brings it back.
    const recall = notice.element.querySelector<HTMLButtonElement>(".viewer-artifact-notice-recall")!;
    expect(recall.hidden).toBe(false);
    expect(document.activeElement).toBe(recall);
    click(recall);
    expect(notice.element.dataset["state"]).toBe("open");

    click(notice.element.querySelector(".viewer-artifact-notice-dismiss")!);
    const sameShare = createArtifactNotice(document, { shareId: "share-a", storage });
    const otherShare = createArtifactNotice(document, { shareId: "share-b", storage });
    expect(sameShare.element.dataset["state"]).toBe("collapsed");
    expect(otherShare.element.dataset["state"]).toBe("open");
  });

  it("reveal() only shows it and moves focus there, whatever state it was in", () => {
    const notice = createArtifactNotice(document, { shareId: "share-c", storage: new MemoryStorage() });
    document.body.append(notice.element);
    click(notice.element.querySelector(".viewer-artifact-notice-dismiss")!);
    notice.reveal();
    expect(notice.element.dataset["state"]).toBe("open");
    expect(document.activeElement).toBe(notice.element.querySelector(".viewer-artifact-notice-dismiss"));
    notice.reveal();
    expect(notice.element.dataset["state"]).toBe("open");
  });

  it("survives unavailable storage", () => {
    const broken = { getItem: () => { throw new DOMException("denied", "SecurityError"); }, setItem: () => { throw new DOMException("denied", "SecurityError"); } };
    const notice = createArtifactNotice(document, { shareId: "x", storage: broken });
    document.body.append(notice.element);
    click(notice.element.querySelector(".viewer-artifact-notice-dismiss")!);
    expect(notice.element.dataset["state"]).toBe("collapsed");
  });
});
