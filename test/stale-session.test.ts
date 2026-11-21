/**
 * A library session saved before Share stopped asking for the whole encryption network. The SDK restores a saved session
 * that covers the current request, so such a session comes back holding more than it should. Boots the real
 * `src/share/main.ts` (the OpenKey ceremony, the TinyCloud client and the two views are replaced; the saved-session
 * store is the real one) and checks what happens to it on a resumed load.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";
import { defaultEncryptionNetworkForOwner } from "@tinycloud/share-sdk";
import { holdsWholeNetworkAccess } from "../src/share/history-unlock.js";
import { savedLibraryAccount } from "../src/share/library-session.js";

const ADDRESS = "0x1234567890abcdef1234567890abcdef12345678";
const LOWER = `urn:tinycloud:encryption:did:pkh:eip155:1:${ADDRESS}:default`;
const CHECKSUMMED = defaultEncryptionNetworkForOwner({ address: ADDRESS });
const SHARE_PREFIX_PATH = `${CHECKSUMMED}/share/`;

interface Held { readonly path: string; readonly action: string }

const state = vi.hoisted(() => ({
  held: [] as Held[],
  opened: 0,
  reopened: 0,
  networkRequests: 0,
  clientSignOuts: 0,
  openKeySignOuts: 0,
  libraryMounts: 0,
}));

vi.mock("../src/share/openkey-session.js", () => {
  const session = () => ({ address: "0x1234567890abcdef1234567890abcdef12345678", openkey: { signOut: async () => { state.openKeySignOuts += 1; return { revoked: true }; } }, auth: { address: "0x1234567890abcdef1234567890abcdef12345678", keyId: "key", keyType: "MANAGED" } });
  return {
    authenticateWithOpenKey: async () => { state.opened += 1; return session(); },
    reopenOpenKey: async () => { state.reopened += 1; return session(); },
    createTinyCloudClient: async () => ({
      vault: { unlock: async () => ({ ok: true, data: undefined }) },
      // The SDK's own check, as far as this test needs it: an entry is held when a grant names that exact path and action.
      hasPermissions: (entries: Array<{ path: string; actions: string[] }>) => entries.every((entry) => entry.actions.every((action) => state.held.some((held) => held.path === entry.path && held.action === action))),
      getEncryptionNetwork: async () => ({ id: "network" }),
      requestPermissions: async () => { state.networkRequests += 1; return { approved: true }; },
      ensureEncryptionNetwork: async () => ({ id: "network" }),
      signOut: async () => {
        state.clientSignOuts += 1;
        window.localStorage.removeItem("tinycloud-share-library-active-address");
        window.localStorage.removeItem("tinycloud-share-library-0x1234567890abcdef1234567890abcdef12345678");
      },
    }),
    MAX_SHARE_FILE_BYTES: 100 * 1024 * 1024,
    SHARE_APPLICATION_PREFIX: "xyz.tinycloud.share/",
    SHARE_APPLICATION_SPACE: "applications",
    ownerEncryptionNetwork: (address: string) => `urn:tinycloud:encryption:did:pkh:eip155:1:${address.toLowerCase()}:default`,
  };
});
vi.mock("../src/email-share/config.js", async (importOriginal) => ({
  ...(await importOriginal<Record<string, unknown>>()),
  loadSharePublicConfig: async () => ({ version: "tinycloud.share/config-v2", shareOrigin: "https://share.tinycloud.xyz", senderBootstrapNodeOrigin: "https://tee.node.tinycloud.xyz", registryOrigin: "https://registry.tinycloud.xyz", credentialsOrigin: "https://witness.credentials.org", accountlessReceiverEnabled: true }),
}));
vi.mock("../src/share/sender-history.js", () => ({ SenderHistoryRepository: class {} }));
vi.mock("../src/share/sender-home.js", () => ({
  mountSenderHome: (root: HTMLElement) => { state.libraryMounts += 1; const marker = document.createElement("div"); marker.className = "sender-home"; root.replaceChildren(marker); },
  endSenderLibrary: () => undefined,
}));
vi.mock("../src/share/composer.js", () => ({ mountShareComposer: () => undefined, endShareComposer: () => undefined }));

/** What the SDK and Share keep on this device for a signed-in library, so the next load resumes it. */
function saveSession(): void {
  window.localStorage.setItem("tinycloud-share-library-active-address", ADDRESS);
  window.localStorage.setItem(`tinycloud-share-library-${ADDRESS}`, JSON.stringify({ expiresAt: new Date(Date.now() + 86_400_000).toISOString() }));
  window.localStorage.setItem("tinycloud-share-library-openkey-account", JSON.stringify({ address: ADDRESS, keyId: "key", keyType: "MANAGED" }));
}

async function loadPage(): Promise<void> {
  vi.resetModules();
  document.body.innerHTML = '<div id="share-app"></div>';
  window.history.replaceState(null, "", "/share.html#/library");
  vi.stubGlobal("fetch", vi.fn(async () => new Response(null, { status: 401 })));
  await import("../src/share/main.js");
}

beforeEach(() => {
  window.localStorage.clear();
  window.sessionStorage.clear();
  state.held = [];
  state.opened = 0; state.reopened = 0; state.networkRequests = 0; state.clientSignOuts = 0; state.openKeySignOuts = 0; state.libraryMounts = 0;
});

const decrypt = (path: string): Held => ({ path, action: "decrypt" });
const create = (path: string): Held => ({ path, action: "network.create" });

describe("what counts as the old whole-network access", () => {
  const fake = (held: Held[]) => ({ hasPermissions: (entries: Array<{ path: string; actions: string[] }>) => entries.every((entry) => entry.actions.every((action) => held.some((grant) => grant.path === entry.path && grant.action === action))) }) as never;

  it("the two spellings of the network differ, so both are looked for", () => {
    expect(CHECKSUMMED).not.toBe(LOWER);
  });

  it.each([
    ["decrypt on the lowercase network", [decrypt(LOWER)]],
    ["decrypt on the checksummed network", [decrypt(CHECKSUMMED)]],
    ["network.create on the lowercase network", [create(LOWER)]],
    ["network.create on the checksummed network", [create(CHECKSUMMED)]],
    ["both, as the old sign-in asked", [decrypt(LOWER), create(LOWER)]],
  ])("is found: %s", (_name, held) => {
    expect(holdsWholeNetworkAccess(fake(held), ADDRESS)).toBe(true);
  });

  it.each([
    ["decrypt under share/ only (what sign-in asks now)", [decrypt(SHARE_PREFIX_PATH)]],
    ["decrypt under a share/ path of the lowercase spelling", [decrypt(`${LOWER}/share/`)]],
    ["a path that merely starts with the network id", [decrypt(`${CHECKSUMMED}-other`), create(`${LOWER}/share/x`)]],
    ["nothing on the network", []],
  ])("is not found: %s", (_name, held) => {
    expect(holdsWholeNetworkAccess(fake(held), ADDRESS)).toBe(false);
  });
});

describe("a saved session from before the change, restored on load", () => {
  it.each([
    ["lowercase", [decrypt(LOWER), create(LOWER)]],
    ["checksummed", [decrypt(CHECKSUMMED), create(CHECKSUMMED)]],
    ["decrypt only", [decrypt(LOWER)]],
    ["network.create only", [create(CHECKSUMMED)]],
  ])("is not kept (%s): signed out here, no saved account, and the wall is a clean first sign-in", async (_name, held) => {
    state.held = held;
    saveSession();
    expect(savedLibraryAccount()).toBeDefined();
    await loadPage();
    await vi.waitFor(() => expect(state.clientSignOuts).toBe(1));
    await vi.waitFor(() => expect(document.querySelector("h2")?.textContent).toBe("One key, your files"));
    expect(savedLibraryAccount()).toBeUndefined();
    expect(window.localStorage.getItem("tinycloud-share-library-active-address")).toBeNull();
    expect(window.localStorage.getItem("tinycloud-share-library-openkey-account")).toBeNull();
    const button = document.querySelector<HTMLButtonElement>("button[type=submit]")!;
    expect(button.hidden).toBe(false);
    expect(button.disabled).toBe(false);
    expect(button.textContent).toBe("Continue with OpenKey");
    expect(document.querySelector(".auth-status")?.textContent).toBe("");
    expect(state.libraryMounts).toBe(0);
    expect(state.openKeySignOuts).toBe(0);
  });

  it("asks OpenKey nothing after it is dropped: a reload stays on the wall until the person presses the button", async () => {
    state.held = [decrypt(LOWER), create(LOWER)];
    saveSession();
    await loadPage();
    await vi.waitFor(() => expect(document.querySelector("h2")?.textContent).toBe("One key, your files"));
    // The one resume that found the old session is the only OpenKey call there has been.
    expect(state.reopened).toBe(1);
    expect(state.opened).toBe(0);
    expect(state.networkRequests).toBe(0);

    await loadPage();
    await vi.waitFor(() => expect(document.querySelector("form.auth-form")).not.toBeNull());
    await vi.dynamicImportSettled();
    expect(document.querySelector("h2")?.textContent).toBe("One key, your files");
    const button = document.querySelector<HTMLButtonElement>("button[type=submit]")!;
    expect(button.hidden).toBe(false);
    expect(button.disabled).toBe(false);
    expect(button.textContent).toBe("Continue with OpenKey");
    expect(document.querySelector(".auth-status")?.textContent).toBe("");
    expect(state.reopened).toBe(1);
    expect(state.opened).toBe(0);
    expect(state.networkRequests).toBe(0);
    expect(state.openKeySignOuts).toBe(0);
  });

  it("is kept when it holds decrypt under share/ only", async () => {
    state.held = [decrypt(SHARE_PREFIX_PATH)];
    saveSession();
    await loadPage();
    await vi.waitFor(() => expect(state.libraryMounts).toBe(1));
    expect(state.clientSignOuts).toBe(0);
    expect(savedLibraryAccount()).toBeDefined();
    expect(document.querySelector(".sender-home")).not.toBeNull();
  });
});
