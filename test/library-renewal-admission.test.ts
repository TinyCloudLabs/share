/** Library restoration uses SDK admission before account and library operations. Details: TC-2872 */
import { beforeEach, expect, it, vi } from "vitest";
import { createTinyCloudClient, reopenOpenKey, shareManifest, SHARE_MANIFEST_SCOPE, signInWithManifest } from "../src/share/openkey-session.js";
import { LIBRARY_SESSION_PREFIX } from "../src/share/library-session.js";
import type { SharePublicConfig } from "../src/email-share/config.js";

const state = vi.hoisted(() => ({ order: [] as string[], admitted: true, manifestCovered: true, effectiveExpiry: 2_000_000_000, sessionAddress: "0x1234567890abcdef1234567890abcdef12345678" }));
vi.mock("@openkey/sdk", () => ({ OpenKey: class { disconnect() {} }, OpenKeyProvider: class {} }));
vi.mock("@tinycloud/web-sdk", () => ({ TinyCloudWeb: class {
  sessionRestoreStatus = "restored";
  spaceId = "applications";
  account = { spaces: { get: async () => { state.order.push("account-read"); return { ok: true, data: {} }; } } };
  async restoreSessionWithRenewal(authorization: string, address: string) {
    state.order.push("sdk-admission");
    expect(authorization).toBe("owner-approved-lease");
    expect(address).toBe(state.sessionAddress);
    return state.admitted ? { status: "restored", session: { address, siwe: "Expiration Time: 2000-01-01T00:00:00Z" } } : { status: "restore-failed" };
  }
  hasPermissions(resources: unknown[]) { state.order.push("manifest-check"); expect(resources.length).toBeGreaterThan(0); return state.manifestCovered; }
  async getRenewalEffectiveExpiry() { state.order.push("effective-expiry"); return state.effectiveExpiry; }
  async signIn() { state.order.push("fresh-sign-in"); throw new Error("unexpected-owner-approval"); }
  async signOut() { state.order.push("dispose"); }
  async ensureOwnedSpaceHosted() { state.order.push("host"); return "account"; }
} }));
const config: SharePublicConfig = { version: "tinycloud.share/config-v2", shareOrigin: "https://share.tinycloud.xyz", senderBootstrapNodeOrigin: "https://tee.node.tinycloud.xyz", registryOrigin: "https://registry.tinycloud.xyz", credentialsOrigin: "https://witness.credentials.org", accountlessReceiverEnabled: false };
const session = () => reopenOpenKey({ address: state.sessionAddress, keyId: "synthetic", keyType: "MANAGED" });
beforeEach(() => { state.order = []; state.admitted = true; state.manifestCovered = true; });

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
