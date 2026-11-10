/**
 * Principle 17 (security-friction row 41). Share's library session is saved on the device by the web SDK, with the
 * OpenKey account it belongs to beside it, and a load with one there resumes it by itself: no tap, and for a managed
 * key no OpenKey window. The page decides before the SDK loads, so it reads the SDK's storage layout itself; these
 * tests write records with the SDK's own BrowserSessionStorage, so a change to that layout fails here instead of
 * silently showing the wrong screen.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { BrowserSessionStorage, TinyCloudWeb } from "@tinycloud/web-sdk";
import type { AuthResult } from "@openkey/sdk";
import { forgetLibraryAccount, LIBRARY_SESSION_PREFIX, saveLibraryAccount, savedLibraryAccount } from "../src/share/library-session.js";
import { endSenderSession } from "../src/share/sender-chrome.js";
import type { OpenKeyShareSession } from "../src/share/openkey-session.js";

const calls = vi.hoisted(() => ({ connects: 0, reopens: 0, clientFailures: 0, clientGate: undefined as Promise<void> | undefined, clientWaiting: false }));
vi.mock("../src/share/openkey-session.js", () => {
  const session = (auth: AuthResult) => ({ address: auth.address, openkey: { signOut: async () => ({ requestId: "r", revoked: true }), disconnect: () => undefined }, auth });
  return {
    authenticateWithOpenKey: async () => { calls.connects += 1; return session({ address: ADDRESS, keyId: "key-1", keyType: "MANAGED" }); },
    reopenOpenKey: (auth: AuthResult) => { calls.reopens += 1; return session(auth); },
    createTinyCloudClient: async () => {
      calls.clientWaiting = calls.clientGate !== undefined;
      await calls.clientGate;
      // A restore that fails and a fresh approval that is cancelled, as one failure.
      if (calls.clientFailures > 0) { calls.clientFailures -= 1; throw Object.assign(new Error("closed"), { code: "USER_CANCELLED" }); }
      return { vault: { unlock: async () => ({ ok: true, data: undefined }) }, signOut: async () => undefined, spaceId: "applications" };
    },
    MAX_SHARE_FILE_BYTES: 100 * 1024 * 1024,
    SHARE_APPLICATION_PREFIX: "xyz.tinycloud.share/",
    SHARE_APPLICATION_SPACE: "applications",
    ownerEncryptionNetwork: (address: string) => address,
  };
});
vi.mock("../src/email-share/config.js", async (importOriginal) => ({
  ...(await importOriginal<Record<string, unknown>>()),
  loadSharePublicConfig: async () => ({ version: "tinycloud.share/config-v2", shareOrigin: "https://share.tinycloud.xyz", senderBootstrapNodeOrigin: "https://tee.node.tinycloud.xyz", registryOrigin: "https://registry.tinycloud.xyz", credentialsOrigin: "https://witness.credentials.org", accountlessReceiverEnabled: true }),
}));
vi.mock("../src/share/sender-history.js", () => ({ SenderHistoryRepository: class { constructor(_vault: unknown) {} } }));
vi.mock("../src/share/sender-home.js", () => ({
  mountSenderHome: (root: HTMLElement) => { const marker = document.createElement("div"); marker.className = "sender-home"; root.replaceChildren(marker); },
  endSenderLibrary: () => undefined,
}));
vi.mock("../src/share/composer.js", () => ({ mountShareComposer: () => undefined, endShareComposer: () => undefined }));

const ADDRESS = "0x1234567890AbcdEF1234567890aBcdef12345678";
const HOUR = 60 * 60 * 1000;
const MANAGED: AuthResult = { address: ADDRESS, keyId: "key-1", keyType: "MANAGED" };

/** Saves a well-formed session record the way the web SDK does, under `prefix`, ending `ms` from now, and the account Share keeps beside it. */
async function saveSession(prefix: string, ms: number, account: AuthResult | null = MANAGED): Promise<BrowserSessionStorage> {
  const storage = new BrowserSessionStorage({ storage: localStorage, keyPrefix: prefix });
  const now = Date.now();
  await storage.save(ADDRESS, {
    address: ADDRESS,
    chainId: 1,
    sessionKey: JSON.stringify({ kty: "OKP", crv: "Ed25519", x: "x" }),
    siwe: "share.tinycloud.xyz wants you to sign in",
    signature: "0xsignature",
    tinycloudSession: { delegationHeader: { Authorization: "Bearer x" }, delegationCid: "bafy", spaceId: "space", verificationMethod: "did:key:z" },
    expiresAt: new Date(now + ms).toISOString(),
    createdAt: new Date(now).toISOString(),
    version: "1",
  });
  if (account !== null) saveLibraryAccount(account);
  return storage;
}

beforeEach(() => { localStorage.clear(); calls.connects = 0; calls.reopens = 0; calls.clientFailures = 0; });
afterEach(() => { vi.useRealTimers(); });

describe("savedLibraryAccount reads what the web SDK saved", () => {
  it("finds the account of an unexpired library session, and nothing once the SDK clears it (sign-out)", async () => {
    const storage = await saveSession(LIBRARY_SESSION_PREFIX, HOUR);
    expect(savedLibraryAccount(localStorage)).toEqual(MANAGED);
    await storage.clear(ADDRESS);
    expect(savedLibraryAccount(localStorage)).toBeUndefined();
  });

  it("does not offer an expired session", async () => {
    await saveSession(LIBRARY_SESSION_PREFIX, HOUR);
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(Date.now() + HOUR + 1);
    expect(savedLibraryAccount(localStorage)).toBeUndefined();
  });

  it("ignores a session another Share sign-in saved under its own prefix (an app the runner opened)", async () => {
    await saveSession("tinycloud-share-runner-78797a", HOUR);
    expect(savedLibraryAccount(localStorage)).toBeUndefined();
  });

  it("offers nothing when the saved account is missing, forgotten, or another account's", async () => {
    await saveSession(LIBRARY_SESSION_PREFIX, HOUR, null);
    expect(savedLibraryAccount(localStorage)).toBeUndefined();
    saveLibraryAccount({ ...MANAGED, address: "0x9999999999999999999999999999999999999999" });
    expect(savedLibraryAccount(localStorage)).toBeUndefined();
    saveLibraryAccount(MANAGED);
    expect(savedLibraryAccount(localStorage)).toEqual(MANAGED);
    forgetLibraryAccount();
    expect(savedLibraryAccount(localStorage)).toBeUndefined();
  });

  it("answers no when the browser blocks storage or a record is not JSON", async () => {
    expect(savedLibraryAccount({ getItem: () => { throw new DOMException("blocked", "SecurityError"); } })).toBeUndefined();
    localStorage.setItem(`${LIBRARY_SESSION_PREFIX}active-address`, ADDRESS.toLowerCase());
    localStorage.setItem(`${LIBRARY_SESSION_PREFIX}${ADDRESS.toLowerCase()}`, "{not json");
    expect(savedLibraryAccount(localStorage)).toBeUndefined();
  });
});

describe("Sign out removes the saved session from storage", () => {
  it("Share's sign-out, on a real web SDK client set up as the library's, deletes the saved record", async () => {
    await saveSession(LIBRARY_SESSION_PREFIX, HOUR);
    const sessionKey = `${LIBRARY_SESSION_PREFIX}${ADDRESS.toLowerCase()}`;
    expect(localStorage.getItem(sessionKey)).not.toBeNull();
    // As signInWithManifest builds it for the library: persisted under the library prefix, the provider answering as the owner.
    const provider = { request: async ({ method }: { method: string }) => (method === "eth_accounts" ? [ADDRESS] : "0x1") };
    const tinycloud = new TinyCloudWeb({ provider, persistSession: true, sessionStorageKeyPrefix: LIBRARY_SESSION_PREFIX, ui: false });
    const openkey = { signOut: async () => ({ requestId: "r", revoked: true }), disconnect: () => undefined };
    await endSenderSession({ session: { address: ADDRESS, openkey, auth: MANAGED } as unknown as OpenKeyShareSession, tinycloud });
    expect(localStorage.getItem(sessionKey)).toBeNull();
    expect(localStorage.getItem(`${LIBRARY_SESSION_PREFIX}active-address`)).toBeNull();
    expect(savedLibraryAccount(localStorage)).toBeUndefined();
  });
});

describe("the sender sign-in wall (booting the real app)", () => {
  async function boot(): Promise<HTMLElement> {
    vi.resetModules();
    document.body.innerHTML = '<div id="share-app"></div>';
    window.history.replaceState(null, "", "/share.html");
    // main.ts mounts the wall when it loads: each boot is a fresh module load, like a page reload.
    await import("../src/share/main.js");
    return document.getElementById("share-app")!;
  }
  const continueButton = (root: HTMLElement) => root.querySelector<HTMLButtonElement>("button.auth-button")!;
  const words = (root: HTMLElement) => [root.querySelector(".auth-form h2")?.textContent, continueButton(root).textContent];

  it("resumes a managed key's saved session by itself: no tap, no OpenKey window, nothing to press or claim while it runs", async () => {
    await saveSession(LIBRARY_SESSION_PREFIX, HOUR);
    const root = await boot();
    expect(root.querySelector(".auth-form h2")?.textContent).toBe("Welcome back");
    expect(root.querySelector<HTMLElement>(".auth-copy")!.hidden).toBe(true);
    expect(continueButton(root).hidden).toBe(true);
    await vi.waitFor(() => expect(root.querySelector(".sender-home")).not.toBeNull());
    expect([calls.reopens, calls.connects]).toEqual([1, 0]);
  });

  it("says Connecting from the start of a resume, and Signed in only once the session is back", async () => {
    await saveSession(LIBRARY_SESSION_PREFIX, HOUR);
    let release: () => void = () => undefined;
    // Executor form: the Node 20 test runtime has no Promise.withResolvers.
    calls.clientGate = new Promise((resolve) => { release = resolve; });
    const statuses: string[] = [];
    const root = await boot();
    const status = root.querySelector(".auth-status")!;
    statuses.push(status.textContent ?? "");
    new MutationObserver(() => statuses.push(status.textContent ?? "")).observe(status, { childList: true, characterData: true, subtree: true });
    // Held where the session is being restored: nothing may have said "Signed in" yet.
    await vi.waitFor(() => expect(calls.clientWaiting).toBe(true));
    expect(statuses.length).toBeGreaterThan(0);
    expect(statuses.every((text) => text === "Connecting to your encrypted TinyCloud…")).toBe(true);
    release(); calls.clientGate = undefined;
    await vi.waitFor(() => expect(root.querySelector(".sender-home")).not.toBeNull());
    expect(statuses.at(-1)).toBe("Signed in. Loading your shares…");
  });

  it("opens OpenKey to resume an external wallet's session: its signatures route through connect", async () => {
    await saveSession(LIBRARY_SESSION_PREFIX, HOUR, { ...MANAGED, keyType: "EXTERNAL" });
    const root = await boot();
    await vi.waitFor(() => expect(root.querySelector(".sender-home")).not.toBeNull());
    expect([calls.reopens, calls.connects]).toEqual([0, 1]);
  });

  it("shows Continue when resuming fails, and Continue signs in through OpenKey", async () => {
    await saveSession(LIBRARY_SESSION_PREFIX, HOUR);
    calls.clientFailures = 1;
    const root = await boot();
    await vi.waitFor(() => expect(continueButton(root).hidden).toBe(false));
    expect(words(root)).toEqual(["Welcome back", "Continue"]);
    expect(root.querySelector<HTMLElement>(".auth-copy")!.hidden).toBe(false);
    expect(root.querySelector(".auth-copy")?.textContent).toBe("Sign in with OpenKey to continue.");
    expect(continueButton(root).disabled).toBe(false);
    expect(document.activeElement).toBe(continueButton(root));
    expect(root.querySelector(".sender-home")).toBeNull();
    continueButton(root).click();
    await vi.waitFor(() => expect(root.querySelector(".sender-home")).not.toBeNull());
    expect([calls.reopens, calls.connects]).toEqual([1, 1]);
  });

  it("asks for a plain sign-in when nothing is saved, or what is saved has expired", async () => {
    expect(words(await boot())).toEqual(["One key, your files", "Continue with OpenKey"]);
    await saveSession(LIBRARY_SESSION_PREFIX, HOUR);
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(Date.now() + HOUR + 1);
    expect(words(await boot())).toEqual(["One key, your files", "Continue with OpenKey"]);
    expect(calls.reopens).toBe(0);
  });

  it("forgets the account at Sign out, and a resumed tab with no OpenKey sign-in says Share alone signed out", async () => {
    await saveSession(LIBRARY_SESSION_PREFIX, HOUR);
    sessionStorage.clear();
    const root = await boot();
    await vi.waitFor(() => expect(root.querySelector(".sender-signout")).not.toBeNull());
    root.querySelector<HTMLButtonElement>(".sender-signout")!.click();
    root.querySelector<HTMLButtonElement>(".sender-confirm-dialog .sender-confirm-revoke")!.click();
    await vi.waitFor(() => expect(root.querySelector(".auth-shell")).not.toBeNull());
    expect(words(root)).toEqual(["One key, your files", "Continue with OpenKey"]);
    expect(root.querySelector(".auth-status")?.textContent).toBe("Signed out of Share. To sign out of OpenKey too, use openkey.so.");
    expect(localStorage.getItem(`${LIBRARY_SESSION_PREFIX}openkey-account`)).toBeNull();
  });
});
