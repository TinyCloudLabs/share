/** Library bootstrap keeps the selected device session through its app commit. Details: TC-2872 */
import { beforeEach, expect, it, vi } from "vitest";
import { forgetLibraryAccount, LIBRARY_SESSION_PREFIX, saveLibraryAccount } from "../src/share/library-session.js";

const state = vi.hoisted(() => ({ changeAt: "", changeKind: "", homeMounts: 0, chromeMounts: 0, signOuts: 0, onSignedOut: undefined as undefined | (() => void), clientGate: undefined as Promise<void> | undefined, clientWaiting: false }));
const address = "0x1234567890abcdef1234567890abcdef12345678";
const otherAddress = "0x2234567890abcdef1234567890abcdef12345678";
const auth = { address, keyId: "synthetic", keyType: "MANAGED" as const };
function seed(): void {
  localStorage.setItem(`${LIBRARY_SESSION_PREFIX}active-address`, address);
  localStorage.setItem(`${LIBRARY_SESSION_PREFIX}${address}`, JSON.stringify({ signature: "synthetic-signature", expiresAt: "2000-01-01T00:00:00Z" }));
  saveLibraryAccount(auth);
}
function atStage(stage: string): void {
  if (state.changeAt !== stage) return;
  if (state.changeKind === "account-switch") {
    localStorage.setItem(`${LIBRARY_SESSION_PREFIX}active-address`, otherAddress);
    saveLibraryAccount({ address: otherAddress, keyId: "other", keyType: "MANAGED" });
  } else {
    forgetLibraryAccount();
    if (state.changeKind === "sign-out-and-resume") seed();
  }
}
const client = { vault: { unlock: async () => { atStage("vault"); return { ok: true }; } }, signOut: async () => { state.signOuts += 1; } };
vi.mock("@tinycloud/web-sdk", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@tinycloud/web-sdk")>();
  return { ...actual, BrowserSessionStorage: class extends actual.BrowserSessionStorage {
    async loadRenewalCandidate(requested: string) { atStage("candidate"); return { status: "renewal-candidate" as const, data: JSON.parse(localStorage.getItem(`${LIBRARY_SESSION_PREFIX}${requested}`) ?? "null") }; }
  } };
});
vi.mock("../src/share/openkey-session.js", () => ({
  reopenOpenKey: (account: typeof auth) => ({ address: account.address, auth: account, openkey: {} }),
  createTinyCloudClient: async () => { if (state.clientGate !== undefined) { state.clientWaiting = true; await state.clientGate; } atStage("client"); return client; },
}));
vi.mock("../src/email-share/config.js", () => ({ loadSharePublicConfig: async () => { atStage("config"); return { shareOrigin: "https://share.tinycloud.xyz" }; } }));
vi.mock("../src/share/sender-history.js", () => ({ SenderHistoryRepository: class {} }));
vi.mock("../src/share/sender-chrome.js", () => ({ get mountSenderChrome() { atStage("chrome-module"); return (_root: HTMLElement, options: { onSignedOut(): void }) => { state.chromeMounts += 1; state.onSignedOut = options.onSignedOut; }; } }));
vi.mock("../src/share/sender-home.js", () => ({ mountSenderHome: (root: HTMLElement) => { state.homeMounts += 1; root.classList.add("sender-home"); }, endSenderLibrary: () => undefined }));
vi.mock("../src/share/node-status.js", () => ({ createNodeStatusReader: () => ({}) }));
beforeEach(() => {
  vi.resetModules();
  state.changeAt = ""; state.changeKind = ""; state.homeMounts = 0; state.chromeMounts = 0; state.signOuts = 0; state.onSignedOut = undefined; state.clientGate = undefined; state.clientWaiting = false;
  localStorage.clear(); sessionStorage.clear(); document.body.innerHTML = '<div id="share-app"></div>';
  window.history.replaceState(null, "", "/share"); seed();
});

it("commits the unchanged selected library after unlock", async () => {
  const { resumeLibraryWithRenewal } = await import("../src/share/main.js");
  expect(await resumeLibraryWithRenewal("explicit-lease", document.createElement("p"))).toBe(client);
  await vi.waitFor(() => expect(state.homeMounts).toBe(1));
  expect(state.chromeMounts).toBe(1);
});

for (const stage of ["candidate", "chrome-module", "config", "client", "vault"]) {
  for (const change of ["sign-out", "sign-out-and-resume", "account-switch"]) {
    it(`refuses ${change} during ${stage} before saving or rendering the app`, async () => {
      const { resumeLibraryWithRenewal } = await import("../src/share/main.js");
      state.changeAt = stage; state.changeKind = change;
      await expect(resumeLibraryWithRenewal("explicit-lease", document.createElement("p"))).rejects.toThrow();
      expect(state.homeMounts).toBe(0); expect(state.chromeMounts).toBe(0);
      expect(state.signOuts).toBe(stage === "client" || stage === "vault" ? 1 : 0);
      const saved = localStorage.getItem(`${LIBRARY_SESSION_PREFIX}openkey-account`);
      if (change === "sign-out") expect(saved).toBeNull();
      if (change === "account-switch") expect(JSON.parse(saved!).address).toBe(otherAddress);
    });
  }
}

it("cancels an older pending authentication attempt when the current library signs out", async () => {
  const { resumeLibraryWithRenewal } = await import("../src/share/main.js");
  await resumeLibraryWithRenewal("explicit-lease", document.createElement("p"));
  await vi.waitFor(() => expect(state.homeMounts).toBe(1));
  let release: (() => void) | undefined;
  state.clientGate = new Promise<void>((resolve) => { release = resolve; });
  const pending = resumeLibraryWithRenewal("explicit-lease", document.createElement("p"));
  await vi.waitFor(() => expect(state.clientWaiting).toBe(true));
  state.onSignedOut?.(); release?.();
  await expect(pending).rejects.toThrow("library-auth-cancelled");
  expect(state.signOuts).toBe(1); expect(state.homeMounts).toBe(1); expect(state.chromeMounts).toBe(1);
  expect(localStorage.getItem(`${LIBRARY_SESSION_PREFIX}openkey-account`)).toBeNull();
});
