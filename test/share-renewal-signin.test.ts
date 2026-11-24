// @vitest-environment jsdom
import { OpenKey } from "@openkey/sdk";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { createTinyCloudClient, signInWithManifest, SHARE_MANIFEST_SCOPE, shareManifest, SignInOptionError, authenticateWithOpenKey } from "../src/share/openkey-session.js";
import { forgetLibraryAccount, LIBRARY_SESSION_PREFIX, savedLibraryAccount } from "../src/share/library-session.js";
import { hasRenewalReceipt, loadRenewalReceipt, RENEWAL_RESTORE_UNAVAILABLE, saveRenewalReceipt, SIGN_IN_RENEWAL_ASK } from "../src/share/renewal-store.js";

const ADDRESS = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";
const PREFIX = LIBRARY_SESSION_PREFIX;

const recapSiwe = (att: Record<string, Record<string, unknown[]>>): string =>
  `app.example wants you to sign in with your Ethereum account:\n${ADDRESS}\n\nSign in.\n\nResources:\n- urn:recap:${Buffer.from(JSON.stringify({ att })).toString("base64url")}`;
const ASKED = recapSiwe({ "tinycloud:space-a/kv/one": { "tinycloud.kv/get": [] } });

const LEASE = { version: 1, approvedAt: "2026-11-21T12:00:00.000Z", receipt: { leaseExpiresAt: "2999-01-01T00:00:00.000Z" } };

const state = vi.hoisted(() => ({
  clients: [] as Array<{ config: Record<string, unknown> }>,
  authorized: [] as Array<Record<string, unknown>>,
  answer: undefined as undefined | (() => Promise<unknown>),
  signIns: 0,
  restores: [] as Array<{ lease: string; address: string }>,
  cleanups: 0,
  signedOut: 0,
  restoreResult: "restored" as "restored" | "throws" | "revoked" | "expired-status" | "failed-status" | "lease-expired" | "forbidden" | "unknown-refusal" | "timeout" | "http-503-thrown",
  admitted: [] as Array<Record<string, unknown>>,
  leaseToRestore: null as null | { address: string; leaseAuthorization: string },
}));

vi.mock("@openkey/sdk", () => ({
  OpenKey: class {
    disconnect() {}
    async connect() { return { address: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8", keyId: "key-1", keyType: "MANAGED" }; }
    async authorizeTinyCloud(request: Record<string, unknown>) { state.authorized.push(request); return state.answer!(); }
  },
  OpenKeyProvider: class { async request(): Promise<string> { return "0x00"; } },
}));

vi.mock("@tinycloud/web-sdk", () => ({
  TinyCloudWeb: class {
    readonly config: Record<string, unknown>;
    constructor(config: Record<string, unknown>) { this.config = config; state.clients.push({ config }); }
    get sessionRestoreStatus() { return "idle"; }
    get spaceId() { return "applications-space"; }
    readonly account = { spaces: { get: async () => ({ ok: true, data: {} }) } };
    async signIn(): Promise<{ address: string; siwe: string }> {
      state.signIns += 1;
      const openkey = this.config.openkey as { client: { authorizeTinyCloud(request: unknown, opts: unknown): Promise<{ signedMessage: string }> }; mode: string };
      const result = await openkey.client.authorizeTinyCloud({ protocolVersion: 1, siwe: ASKED, jwk: {} }, { mode: openkey.mode });
      return { address: ADDRESS, siwe: result.signedMessage };
    }
    async restoreSessionWithRenewal(lease: string, address: string): Promise<{ status: string; session?: { address: string; siwe: string }; error?: Error }> {
      state.restores.push({ lease, address });
      if (state.restoreResult === "throws") throw new Error("fetch failed");
      if (state.restoreResult === "revoked") throw Object.assign(new Error("inactive"), { code: "RENEWAL_AUTHORITY_INACTIVE" });
      if (state.restoreResult === "lease-expired") throw Object.assign(new Error("expired"), { code: "RENEWAL_LEASE_EXPIRED" });
      if (state.restoreResult === "expired-status") return { status: "expired" };
      if (state.restoreResult === "failed-status") return { status: "restore-failed", error: Object.assign(new Error("node answered"), { status: 503 }) };
      if (state.restoreResult === "forbidden") throw Object.assign(new Error("node answered"), { status: 403 });
      if (state.restoreResult === "unknown-refusal") throw new Error("something unexpected");
      if (state.restoreResult === "timeout") throw Object.assign(new Error("took too long"), { name: "TimeoutError" });
      if (state.restoreResult === "http-503-thrown") throw new Error("wrapped", { cause: new Error("HTTP 503 from the node") });
      return { status: "restored", session: { address, siwe: "restored-siwe" } };
    }
    cleanups = 0;
    cleanup(): void { state.cleanups += 1; }
    async signOut(): Promise<void> { state.signedOut += 1; }
    async ensureOwnedSpaceHosted(name: string): Promise<string> { return name; }
  },
}));

// The receipt checks and the node admission are covered with the real SDK in share-renewal-receipt.test.ts.
vi.mock("../src/share/renewal-receipt.js", () => ({
  renewalRestoreFor: async () => state.leaseToRestore,
  admitSignInRenewal: async (input: Record<string, unknown>) => { state.admitted.push(input); return true; },
}));

const CONFIG = {
  shareOrigin: "https://share.tinycloud.xyz",
  senderBootstrapNodeOrigin: "https://tee.node.tinycloud.xyz",
  registryOrigin: "https://registry.tinycloud.xyz",
} as never;

const signed = (extra: Record<string, unknown> = {}) => async () => ({
  protocolVersion: 1, address: ADDRESS, signature: "0x00", signedMessage: ASKED, selectedActionKeys: [], permissions: [], ...extra,
});

beforeEach(() => {
  state.clients.length = 0;
  state.authorized.length = 0;
  state.signIns = 0;
  state.restores.length = 0;
  state.cleanups = 0;
  state.signedOut = 0;
  state.admitted.length = 0;
  state.restoreResult = "restored";
  state.leaseToRestore = null;
  state.answer = signed();
  localStorage.clear();
});

describe("the library sign-in asks OpenKey for a renewal lease", () => {
  it("sends the 90-day ask with no purpose (so OpenKey's box starts unticked) and lets the owner change the expiry", async () => {
    await createTinyCloudClient(await authenticateWithOpenKey(() => undefined), CONFIG, () => undefined);

    expect(state.authorized[0]).toMatchObject({ protocolVersion: 1, renewal: SIGN_IN_RENEWAL_ASK });
    expect((state.authorized[0] as { renewal?: unknown }).renewal).toEqual({ version: 1, leaseLifetimeSeconds: 90 * 86_400 });
    const openkey = state.clients[0]!.config.openkey as { mode: string; expiryChangeable: boolean; maxExpiresAt: () => number };
    expect(openkey.mode).toBe("iframe");
    expect(openkey.expiryChangeable).toBe(true);
    expect(openkey.maxExpiresAt()).toBeGreaterThan(Date.now());
  });

  it("does not ask when the caller did not choose renewal", async () => {
    await signInWithManifest({ manifest: shareManifest, ...SHARE_MANIFEST_SCOPE, config: CONFIG, versionedSignIn: true });

    expect(state.authorized[0]).not.toHaveProperty("renewal");
    expect(state.clients[0]!.config.openkey).not.toHaveProperty("expiryChangeable");
  });

  it("refuses renewal without the versioned sign-in and a persisted session", async () => {
    for (const options of [{ renewal: true }, { renewal: true, versionedSignIn: true }, { renewal: true, persistSession: true }]) {
      await expect(signInWithManifest({ manifest: shareManifest, ...SHARE_MANIFEST_SCOPE, config: CONFIG, ...options })).rejects.toBeInstanceOf(SignInOptionError);
    }
    expect(state.authorized).toHaveLength(0);
  });
});

describe("with OpenKey's leases off (no lease comes back)", () => {
  it("signs in as a finite session and keeps no receipt, for a result without renewal fields", async () => {
    saveRenewalReceipt(PREFIX, ADDRESS, LEASE);
    await expect(createTinyCloudClient(await authenticateWithOpenKey(() => undefined), CONFIG, () => undefined)).resolves.toBeDefined();

    expect(state.signIns).toBe(1);
    expect(state.admitted).toEqual([]);
    // The earlier session's receipt does not outlive the fresh sign-in.
    expect(hasRenewalReceipt(PREFIX)).toBe(false);
  });

  it("signs in as a finite session when the owner chose finite", async () => {
    state.answer = signed({ renewalChoice: "finite" });
    await expect(createTinyCloudClient(await authenticateWithOpenKey(() => undefined), CONFIG, () => undefined)).resolves.toBeDefined();

    expect(state.admitted).toEqual([]);
    expect(hasRenewalReceipt(PREFIX)).toBe(false);
  });

  it("does not use a lease that came without the owner's choice", async () => {
    state.answer = signed({ renewal: LEASE });
    await createTinyCloudClient(await authenticateWithOpenKey(() => undefined), CONFIG, () => undefined);

    expect(state.admitted).toEqual([]);
  });
});

describe("when the owner turns renewal on", () => {
  it("hands the lease OpenKey signed to its checks and admission, with the account and the time it arrived", async () => {
    state.answer = signed({ renewalChoice: "leased", renewal: LEASE });
    const before = performance.now();
    await createTinyCloudClient(await authenticateWithOpenKey(() => undefined), CONFIG, () => undefined);

    expect(state.admitted).toHaveLength(1);
    expect(state.admitted[0]).toMatchObject({ prefix: PREFIX, address: ADDRESS, renewal: LEASE });
    expect(state.admitted[0]!.arrivedAt as number).toBeGreaterThanOrEqual(before);
  });
});

describe("a reload past the signed end", () => {
  it("restores through the lease with no OpenKey approval", async () => {
    saveRenewalReceipt(PREFIX, ADDRESS, LEASE);
    state.leaseToRestore = { address: ADDRESS, leaseAuthorization: "lease-authorization" };
    const result = await signInWithManifest({
      manifest: shareManifest, ...SHARE_MANIFEST_SCOPE, config: CONFIG, versionedSignIn: true, renewal: true, persistSession: true, sessionPrefix: PREFIX,
      session: { address: ADDRESS, auth: { address: ADDRESS, keyId: "key-1", keyType: "MANAGED" }, openkey: new OpenKey() } as never,
    });

    expect(state.restores).toEqual([{ lease: "lease-authorization", address: ADDRESS }]);
    expect(state.signIns).toBe(0);
    expect(state.authorized).toHaveLength(0);
    expect(hasRenewalReceipt(PREFIX)).toBe(true);
    await result.dispose();
  });

  it("keeps the receipt and the saved session on a transient failure, and the next load tries the lease again", async () => {
    for (const failure of ["throws", "failed-status", "timeout", "http-503-thrown"] as const) {
      saveRenewalReceipt(PREFIX, ADDRESS, LEASE);
      state.leaseToRestore = { address: ADDRESS, leaseAuthorization: "lease-authorization" };
      state.restoreResult = failure;
      state.restores.length = 0;
      state.signIns = 0;
      await expect(createTinyCloudClient(await authenticateWithOpenKey(() => undefined), CONFIG, () => undefined)).rejects.toThrow(RENEWAL_RESTORE_UNAVAILABLE);

      expect(state.restores).toHaveLength(1);
      expect(state.signIns).toBe(0);
      expect(state.authorized).toHaveLength(0);
      expect(hasRenewalReceipt(PREFIX)).toBe(true);
      // The saved session is not signed out (that would clear it): only the attempt's own client is let go.
      expect(state.signedOut).toBe(0);
    }
    expect(state.cleanups).toBe(4);
    // The next load: the network is back, and the lease restores the session with no approval.
    state.restoreResult = "restored";
    state.restores.length = 0;
    await createTinyCloudClient(await authenticateWithOpenKey(() => undefined), CONFIG, () => undefined);
    expect(state.restores).toHaveLength(1);
    expect(state.signIns).toBe(0);
    expect(hasRenewalReceipt(PREFIX)).toBe(true);
  });

  it("drops the receipt and signs in afresh on any refusal that is not clearly transient", async () => {
    for (const answer of ["revoked", "lease-expired", "expired-status", "forbidden", "unknown-refusal"] as const) {
      saveRenewalReceipt(PREFIX, ADDRESS, LEASE);
      state.leaseToRestore = { address: ADDRESS, leaseAuthorization: "lease-authorization" };
      state.restoreResult = answer;
      state.restores.length = 0;
      state.signIns = 0;
      await createTinyCloudClient(await authenticateWithOpenKey(() => undefined), CONFIG, () => undefined);

      expect(state.restores).toHaveLength(1);
      expect(state.signIns).toBe(1);
      expect(hasRenewalReceipt(PREFIX)).toBe(false);
    }
  });

  it("does not try a lease when none is kept", async () => {
    state.leaseToRestore = { address: ADDRESS, leaseAuthorization: "lease-authorization" };
    await createTinyCloudClient(await authenticateWithOpenKey(() => undefined), CONFIG, () => undefined);

    expect(state.restores).toEqual([]);
    expect(state.signIns).toBe(1);
  });
});

describe("resuming the page", () => {
  const save = (expiresAt: string): void => {
    localStorage.setItem(`${PREFIX}active-address`, ADDRESS);
    localStorage.setItem(`${PREFIX}${ADDRESS}`, JSON.stringify({ expiresAt }));
    localStorage.setItem(`${PREFIX}openkey-account`, JSON.stringify({ address: ADDRESS, keyId: "key-1", keyType: "MANAGED" }));
  };

  it("resumes a session past its signed end while its receipt's lease runs", () => {
    save(new Date(Date.now() - 60_000).toISOString());
    expect(savedLibraryAccount()).toBeUndefined();
    saveRenewalReceipt(PREFIX, ADDRESS, LEASE);
    expect(savedLibraryAccount()).toEqual({ address: ADDRESS, keyId: "key-1", keyType: "MANAGED" });
  });

  it("does not resume once the receipt's lease has ended, or for another account's receipt", () => {
    save(new Date(Date.now() - 60_000).toISOString());
    saveRenewalReceipt(PREFIX, ADDRESS, { ...LEASE, receipt: { leaseExpiresAt: new Date(Date.now() - 1000).toISOString() } });
    expect(savedLibraryAccount()).toBeUndefined();
    saveRenewalReceipt(PREFIX, "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC", LEASE);
    expect(savedLibraryAccount()).toBeUndefined();
  });

  it("forgets the receipt at sign-out", () => {
    saveRenewalReceipt(PREFIX, ADDRESS, LEASE);
    forgetLibraryAccount();
    expect(loadRenewalReceipt(PREFIX, ADDRESS)).toBeNull();
  });
});
