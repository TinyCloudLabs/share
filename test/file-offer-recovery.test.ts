import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { createFileOffers, OFFER_COOLDOWN_MS, SAVE_ARMING_MS, SAVE_TIMEOUT_MS, type SaveOutcome, type SaveWith } from "../src/apps/file-offer.ts";

const file = { name: "export.txt", type: "text/plain", bytes: new Uint8Array([42]) };

function mountOffer(save: SaveWith) {
  const title = document.createElement("h1");
  title.tabIndex = -1;
  title.textContent = "Contacts";
  const status = document.createElement("div");
  status.setAttribute("role", "status");
  const offers = createFileOffers({
    view: window,
    appName: () => title.textContent!,
    announce: (text) => { status.textContent = text; },
    focusTarget: title,
    save,
  });
  document.body.replaceChildren(title, status, offers.region, offers.actions);

  return { title, status, offers };
}

beforeEach(() => { vi.useFakeTimers(); });
afterEach(() => {
  vi.useRealTimers();
  document.body.replaceChildren();
});

it("keeps focus on the app title after Save and Dismiss and announces dismissal", async () => {
  const { title, status, offers } = mountOffer(async () => "saved");
  expect(offers.offer(file)).toBe(true);
  vi.advanceTimersByTime(SAVE_ARMING_MS);
  const save = offers.actions.querySelector("button")!;
  save.focus();
  expect(document.activeElement).toBe(save);
  save.click();
  expect(document.activeElement).toBe(title);
  await Promise.resolve();
  expect(offers.actions.children).toHaveLength(0);
  expect(document.activeElement).toBe(title);
  expect(status.textContent).toBe("Saved export.txt.");

  vi.advanceTimersByTime(OFFER_COOLDOWN_MS);
  expect(offers.offer(file)).toBe(true);
  const dismiss = offers.actions.querySelectorAll("button")[1]!;
  dismiss.focus();
  expect(document.activeElement).toBe(dismiss);
  dismiss.click();
  expect(offers.actions.children).toHaveLength(0);
  expect(document.activeElement).toBe(title);
  expect(status.textContent).toBe("File dismissed.");
});

it("restores both actions after the save times out and ignores a late result during a retry", async () => {
  let finishFirst!: (outcome: SaveOutcome) => void;
  let finishRetry!: (outcome: SaveOutcome) => void;
  const saveFile = vi.fn<SaveWith>()
    .mockImplementationOnce(() => new Promise((resolve) => { finishFirst = resolve; }))
    .mockImplementationOnce(() => new Promise((resolve) => { finishRetry = resolve; }));
  const { status, offers } = mountOffer(saveFile);
  expect(offers.offer(file)).toBe(true);
  vi.advanceTimersByTime(SAVE_ARMING_MS);
  const [save, dismiss] = [...offers.actions.querySelectorAll("button")] as [HTMLButtonElement, HTMLButtonElement];
  save.click();
  vi.advanceTimersByTime(SAVE_TIMEOUT_MS - 1);
  expect([save.disabled, dismiss.disabled]).toEqual([true, true]);
  vi.advanceTimersByTime(1);
  expect([save.disabled, dismiss.disabled]).toEqual([false, false]);
  const timeoutMessage = "Share stopped waiting for your browser. Check your downloads; if the file isn't there, save it.";
  expect(status.textContent).toBe(timeoutMessage);

  save.click();
  expect(saveFile).toHaveBeenCalledTimes(2);
  finishFirst("saved");
  await Promise.resolve();
  expect([save.disabled, dismiss.disabled]).toEqual([true, true]);
  expect(status.textContent).toBe(timeoutMessage);
  finishRetry("saved");
  await Promise.resolve();
  expect(offers.actions.children).toHaveLength(0);
  expect(status.textContent).toBe("Saved export.txt.");
});
