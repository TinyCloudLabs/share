// @vitest-environment jsdom
import { beforeEach, describe, expect, it, vi } from "vitest";

const state = vi.hoisted(() => ({
  receive: vi.fn(),
}));

vi.mock("../src/email-share/view.js", () => ({
  renderRecipientInvalid: vi.fn(),
  renderRecipientLoading: vi.fn(),
}));

vi.mock("../src/email-share/config.js", () => ({
  loadSharePublicConfig: async () => ({ shareOrigin: "https://share.tinycloud.xyz" }),
}));

vi.mock("../src/viewer/native-bearer.js", () => {
  class NativeBearerError extends Error {
    readonly reason: string;
    readonly expiresAt?: string;
    constructor(reason: string, message: string) {
      super(message);
      this.reason = reason;
    }
  }
  return {
    NativeBearerError,
    receiveNativeBearerAccess: async (href: string) => {
      state.receive(href);
      throw new NativeBearerError("unavailable", "503");
    },
  };
});

// Loading main.ts pulls in its whole module graph; on a busy host that takes seconds, so wait on the
// outcome, never on a fixed delay.
const WAIT = { timeout: 30_000, interval: 25 };
const SECRET = "FAKE-LINK-SECRET-7d41";

beforeEach(() => {
  vi.resetModules();
  state.receive.mockReset();
  document.body.innerHTML = '<div id="viewer"></div>';
  document.title = "TinyCloud Share";
  window.sessionStorage.clear();
  window.localStorage.clear();
  window.history.replaceState(null, "", `/viewer#tc1=${SECRET}`);
});

describe("Try again on the unavailable screen", () => {
  it("re-runs the read with the same link from memory and writes the link nowhere", { timeout: 60_000 }, async () => {
    const sessionSet = vi.spyOn(Storage.prototype, "setItem");
    const indexedDbOpen = vi.fn();
    Object.defineProperty(window, "indexedDB", { configurable: true, value: { open: indexedDbOpen } });
    const replaceState = vi.spyOn(window.history, "replaceState");
    const pushState = vi.spyOn(window.history, "pushState");
    const cookieSet = vi.spyOn(document, "cookie", "set");

    await import("../src/main.js");
    await vi.waitFor(() => expect(document.querySelector("#viewer h1")?.textContent).toBe("TinyCloud is temporarily unavailable"), WAIT);
    expect(state.receive).toHaveBeenCalledTimes(1);
    const firstHref = state.receive.mock.calls[0]![0] as string;
    expect(firstHref).toContain(SECRET);
    // Arrival already scrubbed the address bar; only that one call may touch history.
    const scrubs = replaceState.mock.calls.length;

    const firstButton = document.querySelector<HTMLButtonElement>("#viewer button.viewer-state-action")!;
    firstButton.click();
    await vi.waitFor(() => expect(state.receive).toHaveBeenCalledTimes(2), WAIT);
    // Every screen swap builds new nodes: a different button means the retry has finished rendering its outcome.
    await vi.waitFor(() => {
      const current = document.querySelector<HTMLButtonElement>("#viewer button.viewer-state-action");
      expect(current).not.toBeNull();
      expect(current).not.toBe(firstButton);
    }, WAIT);
    expect(state.receive.mock.calls[1]![0]).toBe(firstHref);

    expect(sessionSet).not.toHaveBeenCalled();
    expect(indexedDbOpen).not.toHaveBeenCalled();
    expect(cookieSet).not.toHaveBeenCalled();
    expect(pushState).not.toHaveBeenCalled();
    expect(replaceState.mock.calls.length).toBe(scrubs);
    expect(window.sessionStorage.length).toBe(0);
    expect(window.localStorage.length).toBe(0);
    expect(window.location.hash).toBe("");
    expect(JSON.stringify(window.history.state)).not.toContain(SECRET);
    expect(document.title).not.toContain(SECRET);
    expect(document.documentElement.outerHTML).not.toContain(SECRET);
  });
});
