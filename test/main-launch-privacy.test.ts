// @vitest-environment jsdom
import { beforeEach, describe, expect, it, vi } from "vitest";

const state = vi.hoisted(() => ({
  invalid: vi.fn(),
  loadConfig: vi.fn(),
}));

vi.mock("../src/email-share/view.js", () => ({
  renderRecipientInvalid: (...args: unknown[]) => state.invalid(...args),
  renderRecipientLoading: vi.fn(),
}));

vi.mock("../src/email-share/config.js", () => ({
  loadSharePublicConfig: (...args: unknown[]) => state.loadConfig(...args),
}));

beforeEach(() => {
  vi.resetModules();
  state.invalid.mockReset();
  state.loadConfig.mockReset();
  document.body.innerHTML = '<div id="viewer"></div>';
  window.history.replaceState(null, "", "/viewer?sender-launch=1#tc1=secret-capability");
});

describe("viewer launch privacy", () => {
  it("scrubs and rejects the removed sender-launch route before loading configuration", async () => {
    await import("../src/main.js");

    expect(window.location.pathname).toBe("/viewer");
    expect(window.location.search).toBe("");
    expect(window.location.hash).toBe("");
    await vi.waitFor(() => expect(state.invalid).toHaveBeenCalledTimes(1));
    expect(state.loadConfig).not.toHaveBeenCalled();
  });

  it("scrubs and rejects mixed addressed query and fragment material before loading configuration", async () => {
    window.history.replaceState(
      null,
      "",
      "/s/inline?recipient=reader@example.com#v=2&p=sealed-policy-and-key",
    );

    await import("../src/main.js");

    expect(window.location.pathname).toBe("/viewer");
    expect(window.location.search).toBe("");
    expect(window.location.hash).toBe("");
    await vi.waitFor(() => expect(state.invalid).toHaveBeenCalledTimes(1));
    expect(state.loadConfig).not.toHaveBeenCalled();
  });
});
