/**
 * Principle 17 (security-friction row 41). Share's library session is saved on the device by the web SDK, and a
 * reload with one there resumes it by itself, with no tap. The page decides before the SDK loads, so it reads the
 * SDK's storage layout itself; these tests write records with the SDK's own BrowserSessionStorage, so a change to
 * that layout fails here instead of silently showing the wrong screen.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { BrowserSessionStorage } from "@tinycloud/web-sdk";
import { hasSavedLibrarySession, LIBRARY_SESSION_PREFIX } from "../src/share/library-session.js";

const connect = vi.hoisted(() => ({ failures: 0 }));
vi.mock("../src/share/openkey-session.js", () => ({
  authenticateWithOpenKey: async () => {
    if (connect.failures > 0) { connect.failures -= 1; throw Object.assign(new Error("closed"), { code: "USER_CANCELLED" }); }
    return { address: ADDRESS, openkey: { signOut: async () => ({ requestId: "r", revoked: true }), disconnect: () => undefined }, auth: {} };
  },
  createTinyCloudClient: async () => ({ vault: { unlock: async () => ({ ok: true, data: undefined }) }, signOut: async () => undefined, spaceId: "applications" }),
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
  mountSenderHome: (root: HTMLElement) => { const marker = document.createElement("div"); marker.className = "sender-home"; root.replaceChildren(marker); },
  endSenderLibrary: () => undefined,
}));
vi.mock("../src/share/composer.js", () => ({ mountShareComposer: () => undefined, endShareComposer: () => undefined }));

const ADDRESS = "0x1234567890AbcdEF1234567890aBcdef12345678";
const HOUR = 60 * 60 * 1000;

/** Saves a well-formed session record the way the web SDK does, under `prefix`, ending `ms` from now. */
async function saveSession(prefix: string, ms: number): Promise<BrowserSessionStorage> {
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
  return storage;
}

beforeEach(() => { localStorage.clear(); });
afterEach(() => { vi.useRealTimers(); });

describe("hasSavedLibrarySession reads what the web SDK saved", () => {
  it("finds an unexpired library session, and not once the SDK clears it (sign-out)", async () => {
    const storage = await saveSession(LIBRARY_SESSION_PREFIX, HOUR);
    expect(hasSavedLibrarySession(localStorage)).toBe(true);
    await storage.clear(ADDRESS);
    expect(hasSavedLibrarySession(localStorage)).toBe(false);
  });

  it("does not offer an expired session", async () => {
    await saveSession(LIBRARY_SESSION_PREFIX, HOUR);
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(Date.now() + HOUR + 1);
    expect(hasSavedLibrarySession(localStorage)).toBe(false);
  });

  it("ignores a session another Share sign-in saved under its own prefix (an app the runner opened)", async () => {
    await saveSession("tinycloud-share-runner-78797a", HOUR);
    expect(hasSavedLibrarySession(localStorage)).toBe(false);
  });

  it("answers no when the browser blocks storage or the record is not JSON", () => {
    expect(hasSavedLibrarySession({ getItem: () => { throw new DOMException("blocked", "SecurityError"); } })).toBe(false);
    localStorage.setItem(`${LIBRARY_SESSION_PREFIX}active-address`, ADDRESS.toLowerCase());
    localStorage.setItem(`${LIBRARY_SESSION_PREFIX}${ADDRESS.toLowerCase()}`, "{not json");
    expect(hasSavedLibrarySession(localStorage)).toBe(false);
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

  it("resumes a saved session by itself after a reload: no tap, and nothing to press while it runs", async () => {
    await saveSession(LIBRARY_SESSION_PREFIX, HOUR);
    const root = await boot();
    expect(root.querySelector(".auth-form h2")?.textContent).toBe("Welcome back");
    expect(root.querySelector(".auth-copy")?.textContent).toBe("You're still signed in on this device.");
    expect(continueButton(root).hidden).toBe(true);
    await vi.waitFor(() => expect(root.querySelector(".sender-home")).not.toBeNull());
  });

  it("shows Continue when resuming fails (OpenKey's window closed), and Continue resumes", async () => {
    await saveSession(LIBRARY_SESSION_PREFIX, HOUR);
    connect.failures = 1;
    const root = await boot();
    await vi.waitFor(() => expect(continueButton(root).hidden).toBe(false));
    expect(words(root)).toEqual(["Welcome back", "Continue"]);
    expect(continueButton(root).disabled).toBe(false);
    expect(document.activeElement).toBe(continueButton(root));
    expect(root.querySelector(".sender-home")).toBeNull();
    continueButton(root).click();
    await vi.waitFor(() => expect(root.querySelector(".sender-home")).not.toBeNull());
  });

  it("asks for a plain sign-in when nothing is saved, or what is saved has expired", async () => {
    expect(words(await boot())).toEqual(["One key, your files", "Continue with OpenKey"]);
    await saveSession(LIBRARY_SESSION_PREFIX, HOUR);
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(Date.now() + HOUR + 1);
    expect(words(await boot())).toEqual(["One key, your files", "Continue with OpenKey"]);
  });

  it("returns to the plain sign-in after Sign out, not to Welcome back", async () => {
    await saveSession(LIBRARY_SESSION_PREFIX, HOUR);
    const root = await boot();
    await vi.waitFor(() => expect(root.querySelector(".sender-signout")).not.toBeNull());
    root.querySelector<HTMLButtonElement>(".sender-signout")!.click();
    root.querySelector<HTMLButtonElement>(".sender-confirm-dialog .sender-confirm-revoke")!.click();
    await vi.waitFor(() => expect(root.querySelector(".auth-shell")).not.toBeNull());
    expect(words(root)).toEqual(["One key, your files", "Continue with OpenKey"]);
  });
});
