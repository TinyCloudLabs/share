/** Library restoration uses SDK admission before account and library operations. Details: TC-2872 */
import { beforeEach, expect, it, vi } from "vitest";
import { createTinyCloudClient, reopenOpenKey, shareManifest, SHARE_MANIFEST_SCOPE, signInWithManifest } from "../src/share/openkey-session.js";
import { forgetLibraryAccount, LIBRARY_SESSION_PREFIX, saveLibraryAccount } from "../src/share/library-session.js";
import { BrowserSessionStorage } from "@tinycloud/web-sdk";
import type { SharePublicConfig } from "../src/email-share/config.js";

const state = vi.hoisted(() => ({ order: [] as string[], admitted: true, manifestCovered: true, signOutDuringRestore: false, changeAt: "", changeKind: "", effectiveExpiry: 2_000_000_000, sessionAddress: "0x1234567890abcdef1234567890abcdef12345678" }));
vi.mock("@openkey/sdk", () => ({ OpenKey: class { disconnect() {} }, OpenKeyProvider: class {} }));
vi.mock("@tinycloud/web-sdk", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@tinycloud/web-sdk")>();
  return { BrowserSessionStorage: class extends actual.BrowserSessionStorage {
    async loadRenewalCandidate(address: string) { return { status: "renewal-candidate" as const, data: JSON.parse(localStorage.getItem(`${LIBRARY_SESSION_PREFIX}${address.toLowerCase()}`) ?? "null") }; }
  }, TinyCloudWeb: class {
  sessionRestoreStatus = "restored";
  spaceId = "applications";
  account = { spaces: { get: async () => { atStage("account-read"); return { ok: true, data: {} }; } } };
  async restoreSessionWithRenewal(authorization: string, address: string) {
    atStage("sdk-admission");
    expect(authorization).toBe("owner-approved-lease");
    expect(address).toBe(state.sessionAddress);
    if (state.signOutDuringRestore) new BrowserSessionStorage({ keyPrefix: LIBRARY_SESSION_PREFIX }).markSignedOut(address, "0xsynthetic");
    return state.admitted ? { status: "restored", session: { address, signature: "0xsynthetic", siwe: "Expiration Time: 2000-01-01T00:00:00Z" } } : { status: "restore-failed" };
  }
  hasPermissions(resources: unknown[]) { state.order.push("manifest-check"); expect(resources.length).toBeGreaterThan(0); return state.manifestCovered; }
  async getRenewalEffectiveExpiry() { atStage("effective-expiry"); return state.effectiveExpiry; }
  async signIn() { state.order.push("fresh-sign-in"); throw new Error("unexpected-owner-approval"); }
  async signOut() { state.order.push("dispose"); }
  async ensureOwnedSpaceHosted() { atStage("host"); return "account"; }
} }; });
const config: SharePublicConfig = { version: "tinycloud.share/config-v2", shareOrigin: "https://share.tinycloud.xyz", senderBootstrapNodeOrigin: "https://tee.node.tinycloud.xyz", registryOrigin: "https://registry.tinycloud.xyz", credentialsOrigin: "https://witness.credentials.org", accountlessReceiverEnabled: false };
function atStage(stage: string): void {
  state.order.push(stage);
  if (state.changeAt !== stage) return;
  if (state.changeKind === "sign-out") forgetLibraryAccount();
  else {
    const address = "0x2234567890abcdef1234567890abcdef12345678";
    localStorage.setItem(`${LIBRARY_SESSION_PREFIX}active-address`, address);
    saveLibraryAccount({ address, keyId: "other", keyType: "MANAGED" });
  }
}
const session = () => reopenOpenKey({ address: state.sessionAddress, keyId: "synthetic", keyType: "MANAGED" });
beforeEach(() => { state.order = []; state.admitted = true; state.manifestCovered = true; state.signOutDuringRestore = false; state.changeAt = ""; state.changeKind = ""; localStorage.clear();
  localStorage.setItem(`${LIBRARY_SESSION_PREFIX}active-address`, state.sessionAddress);
  localStorage.setItem(`${LIBRARY_SESSION_PREFIX}${state.sessionAddress}`, JSON.stringify({ signature: "0xsynthetic" }));
  saveLibraryAccount({ address: state.sessionAddress, keyId: "synthetic", keyType: "MANAGED" });
});

it("completes SDK admission and manifest coverage before an account read or hosting", async () => {
  await createTinyCloudClient(session(), config, () => undefined, "owner-approved-lease");
  expect(state.order).toEqual(["sdk-admission", "manifest-check", "account-read", "effective-expiry", "host"]);
});

for (const refusal of ["admission", "manifest"] as const) {
  it(`stops after ${refusal} refusal without a fresh approval, account read or hosting`, async () => {
    state.admitted = refusal !== "admission";
    state.manifestCovered = refusal !== "manifest";
    await expect(createTinyCloudClient(session(), config, () => undefined, "owner-approved-lease")).rejects.toThrow();
    expect(state.order).not.toContain("fresh-sign-in");
    expect(state.order).not.toContain("account-read");
    expect(state.order).not.toContain("host");
    expect(state.order.at(-1)).toBe("dispose");
  });
}

it("keeps the explicit lease input scoped to the library manifest and storage prefix", async () => {
  await expect(signInWithManifest({ manifest: shareManifest, ...SHARE_MANIFEST_SCOPE, config, session: session(), persistSession: true, sessionPrefix: LIBRARY_SESSION_PREFIX + "runner-", libraryRenewalAuthorization: "owner-approved-lease" })).rejects.toThrow("library-renewal-scope");
  expect(state.order).toEqual([]);
});

it("honors a sign-out mark written while SDK restore is in flight", async () => {
  state.signOutDuringRestore = true;
  await expect(createTinyCloudClient(session(), config, () => undefined, "owner-approved-lease")).rejects.toThrow("library-renewal-signed-out");
  expect(state.order).toEqual(["sdk-admission", "dispose"]);
});

for (const stage of ["sdk-admission", "account-read", "effective-expiry", "host"] as const) {
  for (const change of ["sign-out", "account-switch"]) {
    it(`refuses ${change} during ${stage} and disposes the partial client`, async () => {
      state.changeAt = stage; state.changeKind = change;
      await expect(createTinyCloudClient(session(), config, (message) => { if (message === "Your encrypted share library is ready.") atStage("ready"); }, "owner-approved-lease")).rejects.toThrow("library-renewal-state-changed");
      const nextStage = { "sdk-admission": "manifest-check", "account-read": "effective-expiry", "effective-expiry": "host", host: "ready" }[stage];
      expect(state.order).not.toContain(nextStage);
      expect(state.order.at(-1)).toBe("dispose");
      expect(state.order).not.toContain("fresh-sign-in");
    });
  }
}

for (const change of ["sign-out", "account-switch"]) {
  it(`refuses ${change} in the final readiness callback`, async () => {
    state.changeAt = "ready"; state.changeKind = change;
    await expect(createTinyCloudClient(session(), config, (message) => { if (message === "Your encrypted share library is ready.") atStage("ready"); }, "owner-approved-lease")).rejects.toThrow("library-renewal-state-changed");
    expect(state.order.at(-1)).toBe("dispose");
  });
}
