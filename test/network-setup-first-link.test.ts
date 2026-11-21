/**
 * The first link of a new account. Boots the real `src/share/main.ts` (the OpenKey ceremony, the TinyCloud client, the
 * history store and the two views are replaced) and drives the sign-in wall and the composer's save step.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";
import { NETWORK_SETUP } from "../src/share/history-copy.js";
import { SENDER_FAILURE } from "../src/share/sender-failure.js";

interface ComposerOptions { readonly persistShare: (input: { readonly share: { readonly record: unknown } }) => Promise<void> }

const state = vi.hoisted(() => ({
  order: [] as string[],
  statusAtRequest: [] as Array<string | null | undefined>,
  networkExists: true,
  approve: true,
  libraryMounts: 0,
  composer: undefined as ComposerOptions | undefined,
}));

vi.mock("../src/share/openkey-session.js", () => ({
  authenticateWithOpenKey: async () => ({ address: "0x1234567890abcdef1234567890abcdef12345678", openkey: {}, auth: {} }),
  createTinyCloudClient: async () => ({
    vault: { unlock: async () => ({ ok: true, data: undefined }) },
    hasPermissions: () => false,
    getEncryptionNetwork: async () => { state.order.push("lookup"); return state.networkExists ? { id: "network" } : null; },
    requestPermissions: async () => {
      state.order.push("request");
      state.statusAtRequest.push(document.querySelector(".auth-status")?.textContent);
      return { approved: state.approve };
    },
    ensureEncryptionNetwork: async () => { state.order.push("ensure"); state.networkExists = true; return { id: "network" }; },
  }),
  MAX_SHARE_FILE_BYTES: 100 * 1024 * 1024,
  SHARE_APPLICATION_PREFIX: "xyz.tinycloud.share/",
  SHARE_APPLICATION_SPACE: "applications",
  ownerEncryptionNetwork: (address: string) => `urn:tinycloud:encryption:did:pkh:eip155:1:${address.toLowerCase()}:default`,
}));
vi.mock("../src/email-share/config.js", async (importOriginal) => ({
  ...(await importOriginal<Record<string, unknown>>()),
  loadSharePublicConfig: async () => ({ version: "tinycloud.share/config-v2", shareOrigin: "https://share.tinycloud.xyz", senderBootstrapNodeOrigin: "https://tee.node.tinycloud.xyz", registryOrigin: "https://registry.tinycloud.xyz", credentialsOrigin: "https://witness.credentials.org", accountlessReceiverEnabled: true }),
}));
vi.mock("../src/share/sender-history.js", () => ({
  SenderHistoryRepository: class {
    constructor(_vault: unknown) {}
    async save(record: unknown): Promise<void> { state.order.push("save"); void record; }
  },
}));
vi.mock("../src/share/sender-home.js", () => ({
  mountSenderHome: (root: HTMLElement) => { state.libraryMounts += 1; const marker = document.createElement("div"); marker.className = "sender-home"; root.replaceChildren(marker); },
  endSenderLibrary: () => undefined,
}));
vi.mock("../src/share/composer.js", () => ({
  mountShareComposer: (root: HTMLElement, options: ComposerOptions) => { state.composer = options; const marker = document.createElement("form"); marker.className = "composer-form"; root.replaceChildren(marker); },
  endShareComposer: () => undefined,
}));

async function signIn(): Promise<void> {
  document.body.innerHTML = '<div id="share-app"></div>';
  window.history.replaceState(null, "", "/share.html#/new");
  vi.stubGlobal("fetch", vi.fn(async () => new Response(null, { status: 401 })));
  localStorage.clear();
  await import("../src/share/main.js");
  await vi.waitFor(() => expect(document.querySelector("form.auth-form")).not.toBeNull());
  document.querySelector<HTMLFormElement>("form.auth-form")!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
}

beforeEach(() => {
  vi.resetModules();
  state.order.length = 0;
  state.statusAtRequest.length = 0;
  state.networkExists = true;
  state.approve = true;
  state.libraryMounts = 0;
  state.composer = undefined;
});

const share = { share: { record: { shareId: "first" } } };

describe("the first link, by account", () => {
  it("an account with its network is asked nothing, at sign-in or at the first save", async () => {
    await signIn();
    await vi.waitFor(() => expect(state.composer).toBeDefined());
    await state.composer!.persistShare(share);
    await state.composer!.persistShare(share);
    expect(state.order).toEqual(["lookup", "save", "save"]);
    expect(document.querySelector(".auth-shell")).toBeNull();
  });

  it("a new account sees the setup line, approves once, and its first link is saved", async () => {
    state.networkExists = false;
    await signIn();
    await vi.waitFor(() => expect(state.composer).toBeDefined());
    expect(state.statusAtRequest).toEqual([NETWORK_SETUP]);
    expect(state.order).toEqual(["lookup", "request", "ensure"]);
    await state.composer!.persistShare(share);
    // The first save found the network ready: no second question, no second lookup.
    expect(state.order).toEqual(["lookup", "request", "ensure", "save"]);
  });

  it("a new account that declines does not reach the library and nothing is saved", async () => {
    state.networkExists = false;
    state.approve = false;
    await signIn();
    await vi.waitFor(() => expect(document.querySelector(".auth-status")?.textContent).toBe(SENDER_FAILURE.signIn));
    expect(state.order).toEqual(["lookup", "request"]);
    expect(state.composer).toBeUndefined();
    expect(state.libraryMounts).toBe(0);
    expect(document.querySelector("button[type=submit]")).not.toBeNull();
  });
});
