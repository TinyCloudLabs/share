/**
 * A new account that declines the one-time encryption setup. Boots the real `src/share/main.ts` (the OpenKey ceremony, the
 * TinyCloud client, the history store and the two views are replaced; the saved-session store is the real one) and
 * checks what the sign-in wall shows and what a reload does afterwards.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";
import { NETWORK_SETUP_DECLINED } from "../src/share/history-copy.js";
import { SENDER_FAILURE } from "../src/share/sender-failure.js";
import { savedLibraryAccount } from "../src/share/library-session.js";

const ADDRESS = "0x1234567890abcdef1234567890abcdef12345678";

const state = vi.hoisted(() => ({
  opened: 0,
  reopened: 0,
  networkRequests: 0,
  clientSignOuts: 0,
  openKeySignOuts: 0,
}));

const SESSION_ACTIVE = "tinycloud-share-library-active-address";
const SESSION_RECORD = `tinycloud-share-library-${ADDRESS}`;

vi.mock("../src/share/openkey-session.js", () => ({
  authenticateWithOpenKey: async () => {
    state.opened += 1;
    return { address: "0x1234567890abcdef1234567890abcdef12345678", openkey: { signOut: async () => { state.openKeySignOuts += 1; return { revoked: true }; } }, auth: { address: "0x1234567890abcdef1234567890abcdef12345678", keyId: "key", keyType: "MANAGED" } };
  },
  reopenOpenKey: async () => { state.reopened += 1; throw new Error("not expected"); },
  createTinyCloudClient: async () => {
    // What the SDK does once signed in: it saves the session; Sign out clears it.
    window.localStorage.setItem("tinycloud-share-library-active-address", "0x1234567890abcdef1234567890abcdef12345678");
    window.localStorage.setItem("tinycloud-share-library-0x1234567890abcdef1234567890abcdef12345678", JSON.stringify({ expiresAt: new Date(Date.now() + 86_400_000).toISOString() }));
    return {
      vault: { unlock: async () => ({ ok: true, data: undefined }) },
      hasPermissions: () => false,
      getEncryptionNetwork: async () => null,
      requestPermissions: async () => { state.networkRequests += 1; return { approved: false }; },
      ensureEncryptionNetwork: async () => ({ id: "network" }),
      signOut: async () => {
        state.clientSignOuts += 1;
        window.localStorage.removeItem("tinycloud-share-library-active-address");
        window.localStorage.removeItem("tinycloud-share-library-0x1234567890abcdef1234567890abcdef12345678");
      },
    };
  },
  MAX_SHARE_FILE_BYTES: 100 * 1024 * 1024,
  SHARE_APPLICATION_PREFIX: "xyz.tinycloud.share/",
  SHARE_APPLICATION_SPACE: "applications",
  ownerEncryptionNetwork: (address: string) => `urn:tinycloud:encryption:did:pkh:eip155:1:${address.toLowerCase()}:default`,
}));
vi.mock("../src/email-share/config.js", async (importOriginal) => ({
  ...(await importOriginal<Record<string, unknown>>()),
  loadSharePublicConfig: async () => ({ version: "tinycloud.share/config-v2", shareOrigin: "https://share.tinycloud.xyz", senderBootstrapNodeOrigin: "https://tee.node.tinycloud.xyz", registryOrigin: "https://registry.tinycloud.xyz", credentialsOrigin: "https://witness.credentials.org", accountlessReceiverEnabled: true }),
}));
vi.mock("../src/share/sender-history.js", () => ({ SenderHistoryRepository: class {} }));
vi.mock("../src/share/sender-home.js", () => ({ mountSenderHome: () => undefined, endSenderLibrary: () => undefined }));
vi.mock("../src/share/composer.js", () => ({ mountShareComposer: () => undefined, endShareComposer: () => undefined }));

async function loadPage(): Promise<void> {
  vi.resetModules();
  document.body.innerHTML = '<div id="share-app"></div>';
  window.history.replaceState(null, "", "/share.html#/new");
  vi.stubGlobal("fetch", vi.fn(async () => new Response(null, { status: 401 })));
  await import("../src/share/main.js");
}

async function declineSetup(): Promise<void> {
  await loadPage();
  await vi.waitFor(() => expect(document.querySelector("form.auth-form")).not.toBeNull());
  document.querySelector<HTMLFormElement>("form.auth-form")!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
  await vi.waitFor(() => expect(document.querySelector(".auth-status")?.textContent).toBe(NETWORK_SETUP_DECLINED));
}

beforeEach(() => {
  window.localStorage.clear();
  window.sessionStorage.clear();
  state.opened = 0; state.reopened = 0; state.networkRequests = 0; state.clientSignOuts = 0; state.openKeySignOuts = 0;
});

describe("declining the one-time encryption setup", () => {
  it("leaves no saved account and no saved session on this device, and does not sign out of OpenKey", async () => {
    await declineSetup();
    expect(window.localStorage.getItem(SESSION_ACTIVE)).toBeNull();
    expect(window.localStorage.getItem(SESSION_RECORD)).toBeNull();
    expect(savedLibraryAccount()).toBeUndefined();
    expect(state.clientSignOuts).toBe(1);
    expect(state.openKeySignOuts).toBe(0);
  });

  it("is a clean first sign-in on reload: the wall, with no OpenKey prompt and nothing resumed", async () => {
    await declineSetup();
    expect(state.networkRequests).toBe(1);
    await loadPage();
    await vi.waitFor(() => expect(document.querySelector("form.auth-form")).not.toBeNull());
    // Let any automatic resume start: its module load and the calls after it have settled.
    await vi.dynamicImportSettled();
    const button = document.querySelector<HTMLButtonElement>("button[type=submit]")!;
    expect(button.hidden).toBe(false);
    expect(button.textContent).toBe("Continue with OpenKey");
    expect(document.querySelector(".auth-status")?.textContent).toBe("");
    expect(state.opened).toBe(1);
    expect(state.reopened).toBe(0);
    expect(state.networkRequests).toBe(1);
  });

  it("says why, with its own line and the button that begins again", async () => {
    await declineSetup();
    const status = document.querySelector(".auth-status")!.textContent;
    expect(status).toBe("Share needs encryption turned on before you can send anything. To turn it on, select Continue with OpenKey and approve the one-time setup.");
    expect(status).not.toBe(SENDER_FAILURE.signIn);
    expect(document.body.textContent).not.toContain("Sign-in could not be completed. Try again.");
    const button = document.querySelector<HTMLButtonElement>("button[type=submit]")!;
    expect(button.hidden).toBe(false);
    expect(button.disabled).toBe(false);
    expect(button.textContent).toBe("Continue with OpenKey");
  });
});
