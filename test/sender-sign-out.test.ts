/**
 * TC-1583. The sender app had no sign-out. This boots the real `src/share/main.ts`
 * with a session (only the OpenKey ceremony, the TinyCloud client and the two
 * views are replaced) and drives the real chrome, dialog and sign-in wall.
 */
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { endSenderSession, OPENKEY_SIGN_OUT_WAIT_MS, SIGNED_OUT_NOTICE, SIGNED_OUT_PARTIAL_NOTICE, SIGN_OUT_BODY } from "../src/share/sender-chrome.js";
import type { OpenKeyShareSession, ShareTinyCloud } from "../src/share/openkey-session.js";

const calls = vi.hoisted(() => ({
  tinycloudSignOut: vi.fn(async () => undefined),
  openkeySignOut: vi.fn(async (): Promise<{ requestId: string; revoked: boolean }> => ({ requestId: "r", revoked: true })),
  disconnect: vi.fn(),
  libraryMounts: 0,
}));

vi.mock("../src/share/openkey-session.js", () => ({
  authenticateWithOpenKey: async () => ({ address: "0x1234567890abcdef1234567890abcdef12345678", openkey: { signOut: calls.openkeySignOut, disconnect: calls.disconnect }, auth: {} }),
  createTinyCloudClient: async () => ({ vault: { unlock: async () => ({ ok: true, data: undefined }) }, signOut: calls.tinycloudSignOut, spaceId: "applications" }),
  MAX_SHARE_FILE_BYTES: 100 * 1024 * 1024,
  SHARE_APPLICATION_PREFIX: "xyz.tinycloud.share/",
  SHARE_APPLICATION_SPACE: "applications",
  ownerEncryptionNetwork: (address: string) => address,
}));
vi.mock("../src/email-share/config.js", async (importOriginal) => ({
  ...(await importOriginal<Record<string, unknown>>()),
  loadSharePublicConfig: async () => ({ version: "tinycloud.share/config-v2", shareOrigin: "https://share.tinycloud.xyz", senderBootstrapNodeOrigin: "https://tee.node.tinycloud.xyz", registryOrigin: "https://registry.tinycloud.xyz", credentialsOrigin: "https://witness.credentials.org", accountlessReceiverEnabled: true }),
}));
vi.mock("../src/share/sender-history.js", () => ({ SenderHistoryRepository: class { constructor(_vault: unknown) {} } }));
vi.mock("../src/share/sender-home.js", () => ({
  mountSenderHome: (root: HTMLElement) => { calls.libraryMounts += 1; const marker = document.createElement("div"); marker.className = "sender-home"; root.replaceChildren(marker); },
}));
vi.mock("../src/share/composer.js", () => ({ mountShareComposer: () => undefined }));

afterEach(() => { vi.useRealTimers(); });

const signInForm = (): HTMLFormElement => document.querySelector<HTMLFormElement>("form.auth-form")!;

describe("sender sign-out (booting the real app)", () => {
  beforeAll(async () => {
    document.body.innerHTML = '<div id="share-app"></div>';
    window.history.replaceState(null, "", "/share.html");
    vi.stubGlobal("fetch", vi.fn(async () => new Response(null, { status: 401 })));
    await import("../src/share/main.js");
    await new Promise((resolve) => setTimeout(resolve, 0));
    signInForm().dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    await vi.waitFor(() => { expect(document.querySelector(".sender-signout")).not.toBeNull(); expect(document.querySelector(".sender-home")).not.toBeNull(); });
  });

  it("puts a Sign out control and the signed-in account in the bar above every screen", () => {
    expect(document.querySelector(".sender-signout")?.textContent).toBe("Sign out");
    expect(document.querySelector(".sender-chrome .sender-account")?.textContent).toBe("0x1234…5678");
    expect(document.querySelector(".sender-home")).not.toBeNull();
  });

  it("asks first, says what it clears and what it leaves alone, and does nothing on Cancel", async () => {
    document.querySelector<HTMLButtonElement>(".sender-signout")!.click();
    const dialog = document.querySelector(".sender-confirm-dialog")!;
    expect(dialog.textContent).toContain(SIGN_OUT_BODY);
    expect(dialog.textContent).toContain("nothing is revoked or deleted");
    dialog.querySelector<HTMLButtonElement>("button")!.click();
    expect(document.querySelector(".sender-confirm-dialog")).toBeNull();
    expect(calls.tinycloudSignOut).not.toHaveBeenCalled();
    expect(calls.openkeySignOut).not.toHaveBeenCalled();
    expect(document.querySelector(".sender-home")).not.toBeNull();
  });

  it("clears the TinyCloud session and OpenKey's sign-in, drops every screen, and returns to the sign-in wall with a notice", async () => {
    document.querySelector<HTMLButtonElement>(".sender-signout")!.click();
    document.querySelector<HTMLButtonElement>(".sender-confirm-dialog .sender-confirm-revoke")!.click();
    await vi.waitFor(() => expect(document.querySelector(".auth-shell")).not.toBeNull());
    expect(calls.tinycloudSignOut).toHaveBeenCalledTimes(1);
    expect(calls.openkeySignOut).toHaveBeenCalledTimes(1);
    expect(document.querySelector(".auth-status")?.textContent).toBe(SIGNED_OUT_NOTICE);
    expect(document.querySelector(".sender-home")).toBeNull();
    expect(document.querySelector(".sender-chrome")).toBeNull();
    expect(window.location.hash).toBe("");
    // A hash change after sign-out must not mount a screen with the dead session.
    const mountsBefore = calls.libraryMounts;
    window.location.hash = "#/library";
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(calls.libraryMounts).toBe(mountsBefore);
    expect(document.querySelector(".sender-home")).toBeNull();
  });
});

describe("endSenderSession", () => {
  const fake = (openkey: Record<string, unknown>, tinycloud: Record<string, unknown> = { signOut: vi.fn(async () => undefined) }) => ({ session: { openkey } as unknown as OpenKeyShareSession, tinycloud: tinycloud as unknown as ShareTinyCloud });

  it("reports true only when OpenKey confirms it ended its own sign-in", async () => {
    expect(await endSenderSession(fake({ signOut: async () => ({ requestId: "r", revoked: true }), disconnect: vi.fn() }))).toBe(true);
    expect(await endSenderSession(fake({ signOut: async () => ({ requestId: "r", revoked: false }), disconnect: vi.fn() }))).toBe(false);
  });

  it("still clears the local session when OpenKey cannot be reached", async () => {
    const tinycloud = { signOut: vi.fn(async () => undefined) };
    const result = await endSenderSession(fake({ signOut: async () => { throw { code: "POPUP_BLOCKED" }; }, disconnect: vi.fn() }, tinycloud));
    expect(result).toBe(false);
    expect(tinycloud.signOut).toHaveBeenCalledTimes(1);
  });

  it("still asks OpenKey when the local sign-out throws", async () => {
    const signOut = vi.fn(async () => ({ requestId: "r", revoked: true }));
    expect(await endSenderSession(fake({ signOut, disconnect: vi.fn() }, { signOut: async () => { throw new Error("boom"); } }))).toBe(true);
    expect(signOut).toHaveBeenCalledTimes(1);
  });

  it("stops waiting for an OpenKey window that never answers, closes it, and says so", async () => {
    vi.useFakeTimers();
    const disconnect = vi.fn();
    const pending = endSenderSession(fake({ signOut: () => new Promise(() => undefined), disconnect }));
    await vi.advanceTimersByTimeAsync(OPENKEY_SIGN_OUT_WAIT_MS);
    expect(await pending).toBe(false);
    expect(disconnect).toHaveBeenCalledTimes(1);
    expect(SIGNED_OUT_PARTIAL_NOTICE).toContain("didn't confirm");
  });
});
