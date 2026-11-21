/**
 * TC-2933. OpenKey's sign-out opens a window that waits for the person to confirm, and the SDK reports no progress.
 * So the wait is long (120 s), the local session clears first, and the signed-out screen does not wait for OpenKey:
 * its answer only picks the notice.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { askOpenKeySignOut, mountSenderChrome, OPENKEY_SIGN_OUT_WAIT_MS, SIGNED_OUT_NOTICE, SIGNED_OUT_PARTIAL_NOTICE } from "../src/share/sender-chrome.js";
import type { OpenKeyShareSession, ShareTinyCloud } from "../src/share/openkey-session.js";

vi.mock("../src/share/confirm-dialog.js", () => ({
  confirmDialog: async (_root: HTMLElement, options: { onConfirm: () => void }) => { options.onConfirm(); return true; },
}));

afterEach(() => { vi.useRealTimers(); });

type Answer = { requestId: string; revoked: boolean };

function openkeyThatAnswersAfter(ms: number, revoked: boolean) {
  const disconnect = vi.fn();
  const signOut = vi.fn(() => new Promise<Answer>((resolve) => { setTimeout(() => resolve({ requestId: "r", revoked }), ms); }));
  return { session: { address: "0x1234567890abcdef1234567890abcdef12345678", openkey: { signOut, disconnect } } as unknown as OpenKeyShareSession, disconnect };
}

describe("OpenKey sign-out wait", () => {
  it("waits 120 seconds", () => {
    expect(OPENKEY_SIGN_OUT_WAIT_MS).toBe(120_000);
  });

  it("counts an answer that arrives at 119 seconds", async () => {
    vi.useFakeTimers();
    const { session, disconnect } = openkeyThatAnswersAfter(119_000, true);
    const outcome = askOpenKeySignOut(session);
    await vi.advanceTimersByTimeAsync(119_000);
    expect(await outcome).toBe("openkey-ended");
    expect(disconnect).not.toHaveBeenCalled();
  });

  it("gives the warning outcome at 120 seconds and closes the window", async () => {
    vi.useFakeTimers();
    const { session, disconnect } = openkeyThatAnswersAfter(500_000, true);
    const outcome = askOpenKeySignOut(session);
    await vi.advanceTimersByTimeAsync(120_000);
    expect(await outcome).toBe("openkey-unconfirmed");
    expect(disconnect).toHaveBeenCalledTimes(1);
  });
});

describe("the signed-out screen", () => {
  function mount(openkeyDelayMs: number, revoked: boolean) {
    const order: string[] = [];
    const { session } = openkeyThatAnswersAfter(openkeyDelayMs, revoked);
    const signOut = vi.fn(async () => { order.push("local-clear"); });
    const parent = document.createElement("div");
    const onSignedOut = vi.fn((notice: Promise<string>) => { order.push("signed-out-screen"); void notice.then(() => order.push("notice")); });
    mountSenderChrome(parent, { session, tinycloud: { signOut } as unknown as ShareTinyCloud, onSignedOut });
    parent.querySelector<HTMLButtonElement>("button.sender-signout")!.click();
    return { order, onSignedOut };
  }

  it("shows at once, after the local clear, before OpenKey answers", async () => {
    vi.useFakeTimers();
    const { order, onSignedOut } = mount(60_000, true);
    await vi.advanceTimersByTimeAsync(0);
    expect(order).toEqual(["local-clear", "signed-out-screen"]);
    expect(onSignedOut).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(60_000);
    expect(order).toEqual(["local-clear", "signed-out-screen", "notice"]);
  });

  it("settles on the confirmed line only when OpenKey says it ended the sign-in", async () => {
    vi.useFakeTimers();
    const confirmed = mount(1_000, true);
    await vi.advanceTimersByTimeAsync(1_000);
    expect(await confirmed.onSignedOut.mock.calls[0]![0]).toBe(SIGNED_OUT_NOTICE);
    const unconfirmed = mount(1_000, false);
    await vi.advanceTimersByTimeAsync(1_000);
    expect(await unconfirmed.onSignedOut.mock.calls[0]![0]).toBe(SIGNED_OUT_PARTIAL_NOTICE);
  });

  it("settles on the warning line when OpenKey never answers", async () => {
    vi.useFakeTimers();
    const silent = mount(600_000, true);
    await vi.advanceTimersByTimeAsync(120_000);
    expect(await silent.onSignedOut.mock.calls[0]![0]).toBe(SIGNED_OUT_PARTIAL_NOTICE);
  });
});
