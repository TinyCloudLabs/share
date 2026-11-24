// @vitest-environment jsdom
import { createHash } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { privateKeyToAccount } from "viem/accounts";
import * as sdk from "@tinycloud/sdk-core";
import type { Manifest, PermissionEntry } from "@tinycloud/web-sdk";
import type { CatalogEntry } from "../src/apps/catalog.ts";
import { openManifest, pathCovers } from "../src/apps/grants.ts";
import { openApp, type RunProgress } from "../src/apps/run.ts";
import { createRunPorts, runnerSessionPrefix } from "../src/apps/run-session.ts";
import { mountRunner } from "../src/apps/run-view.ts";
import type { RenderJsxOptions } from "../src/viewer/jsx-render.js";
import { LIBRARY_SESSION_PREFIX, savedLibraryAccount } from "../src/share/library-session.js";
import { SHARE_MANIFEST_SCOPE, shareManifest, signInWithManifest } from "../src/share/openkey-session.js";
import { loadRenewalReceipt, saveRenewalReceipt } from "../src/share/renewal-store.js";
import { installRecordBytes } from "./stored-fixtures.ts";

const OWNER = privateKeyToAccount("0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d");
const OTHER_ADDRESS = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC";
const NOW = Date.parse("2026-11-23T12:00:00Z");
const HOUR = 3_600_000;
const SIGNED_END = NOW + HOUR;
const RENEWED_END = SIGNED_END + 3 * HOUR;
const LEASE_END = NOW + 90 * 24 * HOUR;
const APP_ID = "xyz.example.contacts";
const RECORD = `${APP_ID}/records/one`;
const CONFIG = {
  version: "tinycloud.share/config-v2",
  shareOrigin: "https://share.example",
  senderBootstrapNodeOrigin: "https://node.example",
  registryOrigin: "https://registry.example",
  credentialsOrigin: "https://credentials.example",
  accountlessReceiverEnabled: false,
} as const;

function appFixture(appId: string, extraPaths: string[] = []) {
  const name = "Test app";
  const description = "A key-value app";
  const manifest = {
    manifest_version: 1, app_id: appId, name, description, space: "applications",
    defaults: false, includePublicSpace: false,
    permissions: ["records/", ...extraPaths].map((path) => ({ service: "tinycloud.kv", path, actions: ["get", "put"] })),
  } satisfies Manifest;
  const files = new Map([
    ["app.jsx", "export default function App() { return null; }"],
    ["manifest.json", JSON.stringify(manifest)],
  ]);
  const hash = (value: string) => createHash("sha256").update(value).digest("hex");
  const pins = [...files].map(([path, value]) => ({ path, sha256: hash(value), size: Buffer.byteLength(value) }));
  const digest = hash(pins.map(({ path, sha256, size }) => `${sha256} ${size} ${path}\n`).join(""));
  const entry: CatalogEntry = {
    app_id: appId, name, description, publisher: { name: "Test" },
    source: { repo: "https://example.test/apps", tag: null, commit: "1234567" },
    manifest: { path: "manifest.json", sha256: hash(files.get("manifest.json")!) },
    bundle: { root: `/apps/b/${digest}/`, files: pins, digest },
    knowledge: null,
  };
  return { entry, manifest, files };
}

const firstVersion = appFixture(APP_ID);
const nextVersion = appFixture(APP_ID, ["settings/"]);
const otherApp = appFixture("xyz.example.other");
const fixtures = [firstVersion, nextVersion, otherApp];

type SavedGrant = { address: string; siwe: string; expiresAt: number; permissions: PermissionEntry[] };
type TestLease = { receipt: { leaseAuthorization: string; leaseExpiresAt: string } };
const saved = new Map<string, SavedGrant>();
const files = new Map<string, string>();
const authorizations: Array<{ siwe: string; renewal?: unknown }> = [];
const connections = vi.fn();
const ordinaryRestores = vi.fn();
const versionedSignIns = vi.fn();
const legacyApprovals = vi.fn();
const restoredLeases = vi.fn();
const reusedGrants = vi.fn();
const stepUps = vi.fn();
let chooseRenewal: boolean;
let renewalStopped: boolean;
let expiryUnavailable: boolean;
let refuseApproval: boolean;

const iso = (time: number) => new Date(time).toISOString();
const lease = (prefix: string, address: string): TestLease => ({
  receipt: { leaseAuthorization: `${prefix}:${address}`, leaseExpiresAt: iso(LEASE_END) },
});
const activeKey = (prefix: string) => `${prefix}active-address`;
const resolve = (manifest: Manifest): PermissionEntry[] => sdk.resolveManifest(sdk.resolveManifestOwner(manifest, sdk.pkhDid(OWNER.address, 1))).resources
  .map(({ service, space, path, actions }) => ({ service, space, path, actions: [...actions] }));

function siwe(address: string, expiresAt: number, permissions: PermissionEntry[]): string {
  const recap = Object.fromEntries(permissions.map(({ service, space, path, actions }) => [
    `tinycloud:${space}/${service.replace("tinycloud.", "")}/${path}`,
    Object.fromEntries(actions.map((action) => [action, [{}]])),
  ]));
  return [
    "share.example wants you to sign in with your Ethereum account:", address, "",
    `Expiration Time: ${iso(expiresAt)}`,
    "Resources:", `- urn:recap:${Buffer.from(JSON.stringify({ att: recap })).toString("base64url")}`,
  ].join("\n");
}

vi.mock("../src/email-share/config.js", () => ({ loadSharePublicConfig: async () => CONFIG }));

vi.mock("../src/viewer/jsx-render.js", () => ({
  renderJsxPage: async (container: HTMLElement, _source: Uint8Array, options: RenderJsxOptions) => {
    const frame = document.createElement("iframe");
    container.append(frame);
    options.onCleanup?.(() => frame.remove());
    options.onState?.("running");
  },
}));

vi.mock("@openkey/sdk", () => ({
  OpenKey: class {
    disconnect() {}
    async connect() {
      connections();
      return { address: OWNER.address, keyId: "test-key", keyType: "MANAGED" };
    }
    async authorizeTinyCloud(request: { siwe: string; renewal?: unknown }) {
      authorizations.push(request);
      if (refuseApproval) throw { code: "USER_CANCELLED" };
      return {
        address: OWNER.address, signedMessage: request.siwe,
        signature: await OWNER.signMessage({ message: request.siwe }),
        renewalChoice: chooseRenewal ? "leased" : "finite",
        renewal: chooseRenewal ? issuedLease : undefined,
      };
    }
    async signMessage({ message }: { message: string }) {
      legacyApprovals();
      if (refuseApproval) throw { code: "USER_CANCELLED" };
      return { signature: await OWNER.signMessage({ message }) };
    }
  },
  OpenKeyProvider: class {},
}));

let issuedLease: TestLease;
interface ClientConfig {
  manifest: Manifest;
  sessionStorageKeyPrefix: string;
  sessionExpirationMs: number;
  openkey?: { client: { authorizeTinyCloud(request: { siwe: string; protocolVersion: number; jwk: object }): Promise<unknown> } };
  signStrategy: { handler(request: { message: string; purpose: string }): Promise<{ approved: boolean }> };
}

vi.mock("@tinycloud/web-sdk", () => {
  class SessionStorageStub {
    constructor(readonly options: { keyPrefix: string }) {}
    activeAddressForRenewal() {
      return localStorage.getItem(activeKey(this.options.keyPrefix)) ?? undefined;
    }
    activeAddress() {
      const grant = saved.get(this.options.keyPrefix);
      if (this.activeAddressForRenewal() === undefined || grant === undefined) return undefined;
      if (grant.expiresAt > Date.now()) return grant.address;
      // The SDK discards the active pointer on an ordinary expired-session lookup.
      localStorage.removeItem(activeKey(this.options.keyPrefix));
      return undefined;
    }
    async loadRenewalCandidate(address: string) {
      const grant = saved.get(this.options.keyPrefix);
      if (grant === undefined || grant.address !== address) return { status: "missing", data: null };
      return { status: grant.expiresAt <= Date.now() ? "renewal-candidate" : "loaded", data: grant };
    }
    async saveRuntimeGrants() {}
  }

  return {
    BrowserSessionStorage: SessionStorageStub,
    deserializeDelegation: (serialized: string) => JSON.parse(serialized),
    TinyCloudWeb: class {
      private grant?: SavedGrant;
      private runtimeGrants: PermissionEntry[] = [];
      sessionRestoreStatus = "idle";
      private effectiveEnd = 0;
      spaceId = "applications";
      account = { spaces: { get: async () => ({ ok: true }) } };

      constructor(readonly config: ClientConfig) {
        versionedSignIns(config.openkey !== undefined);
      }
      get prefix() { return this.config.sessionStorageKeyPrefix; }
      connectWallet() {}
      cleanup() {}
      address() { return this.grant?.address; }
      async ensureOwnedSpaceHosted(name: string) { return name; }

      async restoreSession() {
        ordinaryRestores();
        const address = new SessionStorageStub({ keyPrefix: this.prefix }).activeAddress();
        const grant = saved.get(this.prefix);
        if (address === undefined || grant === undefined) return { status: "missing" };
        return this.restore(grant, grant.expiresAt);
      }
      async restoreSessionWithRenewal(authorization: string, address: string) {
        restoredLeases(authorization, address);
        const grant = saved.get(this.prefix);
        if (grant === undefined || grant.address !== address || authorization !== lease(this.prefix, address).receipt.leaseAuthorization) {
          throw new Error("Wrong lease");
        }
        if (renewalStopped) throw Object.assign(new Error("Renewal stopped"), { code: "RENEWAL_AUTHORITY_INACTIVE" });
        if (Date.now() >= LEASE_END) throw Object.assign(new Error("Lease expired"), { code: "RENEWAL_LEASE_EXPIRED" });
        return this.restore(grant, RENEWED_END);
      }
      async getRenewalEffectiveExpiry() {
        if (expiryUnavailable) throw new Error("No expiry from node");
        return this.effectiveEnd / 1000;
      }
      private restore(grant: SavedGrant, end: number) {
        this.grant = grant;
        this.effectiveEnd = end;
        this.sessionRestoreStatus = "restored";
        return { status: "restored", session: grant };
      }
      async signIn() {
        if (this.grant !== undefined) return this.grant;
        const address = OWNER.address;
        const expiresAt = Date.now() + this.config.sessionExpirationMs;
        const permissions = resolve(this.config.manifest);
        const message = siwe(address, expiresAt, permissions);
        issuedLease = lease(this.prefix, address);
        if (this.config.openkey !== undefined) {
          await this.config.openkey.client.authorizeTinyCloud({ siwe: message, protocolVersion: 1, jwk: {} });
        } else {
          const response = await this.config.signStrategy.handler({ message, purpose: "sign-in" });
          if (!response.approved) throw new Error("Approval refused");
        }
        this.grant = { address, expiresAt, permissions, siwe: message };
        this.effectiveEnd = expiresAt;
        saveGrant(this.prefix, this.grant);
        return this.grant;
      }
      async signOut() {
        saved.delete(this.prefix);
        localStorage.removeItem(activeKey(this.prefix));
      }

      hasPermissions(requested: PermissionEntry[]) {
        const grants = [...(this.grant?.permissions ?? []), ...this.runtimeGrants];
        return requested.every((permission) => permission.actions.every((action) => grants.some((grant) =>
          grant.space === permission.space && grant.service === permission.service
          && grant.actions.includes(action) && pathCovers(grant.path, permission.path),
        )));
      }
      async requestPermissions(permissions: PermissionEntry[]) {
        stepUps(permissions);
        this.runtimeGrants.push(...permissions);
        return { approved: true, delegations: [] };
      }
      async useRuntimeDelegation(permission: PermissionEntry) {
        reusedGrants(permission);
        this.runtimeGrants.push(permission);
      }

      space(name: string) {
        return {
          id: name,
          kv: {
            list: async ({ prefix }: { prefix: string }) => ({
              ok: true, data: { keys: [...files.keys()].filter((key) => key.startsWith(prefix)) },
            }),
            createSignedReadUrl: async (key: string) => ({ ok: true, data: { url: `https://node.example/${key}` } }),
            get: async (key: string) => {
              const permitted = this.hasPermissions([{ service: "tinycloud.kv", space: name, path: key, actions: ["tinycloud.kv/get"] }]);
              return Date.now() < this.effectiveEnd && permitted && files.has(key)
                ? { ok: true, data: { data: files.get(key) } }
                : { ok: false, error: { code: "PERMISSION_DENIED" } };
            },
          },
        };
      }
      sqlForSpace() { return {}; }
    },
  };
});

// The receipt suite verifies real signatures and admission. Here the node controls the lease outcome.
vi.mock("../src/share/renewal-receipt.js", () => ({
  admitSignInRenewal: async ({ prefix, address, renewal }: { prefix: string; address: string; renewal: unknown }) =>
    saveRenewalReceipt(prefix, address, renewal),
  renewalRestoreFor: async (prefix: string) => {
    const grant = saved.get(prefix);
    if (localStorage.getItem(activeKey(prefix)) === null || grant === undefined || grant.expiresAt > Date.now()) return null;
    const receipt = loadRenewalReceipt(prefix, grant.address) as TestLease | null;
    if (receipt === null) return null;
    return { address: grant.address, leaseAuthorization: receipt.receipt.leaseAuthorization };
  },
}));

function install(fixture: typeof firstVersion) {
  const { entry, files: bundle } = fixture;
  const prefix = `${entry.app_id}/app/`;
  for (const [path, value] of bundle) files.set(prefix + path, value);
  files.set(prefix + "install.json", new TextDecoder().decode(installRecordBytes(entry)));
}

function saveGrant(prefix: string, grant: SavedGrant) {
  saved.set(prefix, grant);
  localStorage.setItem(activeKey(prefix), grant.address);
  localStorage.setItem(prefix + grant.address, JSON.stringify({ expiresAt: iso(grant.expiresAt) }));
}

function seedSession(prefix: string, manifest: Manifest, receipt = true, address = OWNER.address) {
  const permissions = resolve(manifest);
  saveGrant(prefix, { address, permissions, expiresAt: SIGNED_END, siwe: siwe(address, SIGNED_END, permissions) });
  if (receipt) saveRenewalReceipt(prefix, OWNER.address, lease(prefix, OWNER.address));
}

const open = (entry = firstVersion.entry, entries = [entry], report: (progress: RunProgress) => void = () => undefined) =>
  openApp(entry.app_id, { ...createRunPorts(), catalog: entries }, report);

beforeEach(() => {
  vi.setSystemTime(NOW);
  vi.clearAllMocks();
  localStorage.clear();
  saved.clear();
  files.clear();
  authorizations.length = 0;
  chooseRenewal = true;
  renewalStopped = false;
  expiryUnavailable = false;
  refuseApproval = false;
  install(firstVersion);
  install(otherApp);
  files.set(RECORD, "test record");
  vi.stubGlobal("fetch", async (url: string) => {
    const bundle = fixtures.find(({ entry }) => url.startsWith(entry.bundle.root));
    const value = bundle !== undefined
      ? bundle.files.get(url.slice(bundle.entry.bundle.root.length))
      : files.get(new URL(url).pathname.slice(1));
    if (value === undefined) return new Response(null, { status: 404 });
    const response = new Response(value);
    return {
      ok: response.ok, status: response.status, headers: response.headers, body: response.body,
      arrayBuffer: async () => new TextEncoder().encode(value).buffer,
    };
  });
});

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

describe("runner renewal", () => {
  it("offers 90 days of standing renewal with the app's signed key-value grant", async () => {
    const { session } = await open();
    const prefix = await runnerSessionPrefix(APP_ID);
    expect(authorizations).toHaveLength(1);
    expect(authorizations[0]?.renewal).toEqual({ version: 1, leaseLifetimeSeconds: 90 * 86_400, purpose: "standing" });
    expect(loadRenewalReceipt(prefix, OWNER.address)).toEqual(lease(prefix, OWNER.address));
    expect(stepUps).not.toHaveBeenCalled();
    expect(await session.data.kvGet(RECORD)).toMatchObject({ ok: true });
  });

  it("keeps the saved account pointer past the signed end while the receipt runs", async () => {
    const prefix = await runnerSessionPrefix(APP_ID);
    seedSession(prefix, openManifest(firstVersion.manifest));
    vi.setSystemTime(SIGNED_END + 1);
    expect(await createRunPorts().hasPersistedSession?.(APP_ID)).toBe(false);
    expect(localStorage.getItem(activeKey(prefix))).toBe(OWNER.address);
    await open();
    expect(localStorage.getItem(activeKey(prefix))).toBe(OWNER.address);
    expect(saved.get(prefix)?.expiresAt).toBe(SIGNED_END);
  });

  it("restores through the lease after the signed end without opening OpenKey", async () => {
    const prefix = await runnerSessionPrefix(APP_ID);
    seedSession(prefix, openManifest(firstVersion.manifest));
    vi.setSystemTime(SIGNED_END + 1);

    const { app, session } = await open();

    expect(restoredLeases).toHaveBeenCalledExactlyOnceWith(lease(prefix, OWNER.address).receipt.leaseAuthorization, OWNER.address);
    expect(connections).not.toHaveBeenCalled();
    expect(authorizations).toEqual([]);
    expect(stepUps).not.toHaveBeenCalled();
    expect(app.authorize("tinycloud.kv", RECORD, "get", false)).toBe(true);
    expect(await session.data.kvGet(RECORD)).toMatchObject({ ok: true });
  });

  it("uses ordinary restore before the signed end and skips it after a successful lease restore", async () => {
    const prefix = await runnerSessionPrefix(APP_ID);
    seedSession(prefix, openManifest(firstVersion.manifest));
    vi.setSystemTime(SIGNED_END - 1);

    const { session } = await open();
    expect(ordinaryRestores).toHaveBeenCalledTimes(1);
    expect(restoredLeases).not.toHaveBeenCalled();
    await session.detach();

    ordinaryRestores.mockClear();
    vi.setSystemTime(SIGNED_END + 1);
    await open();

    expect(restoredLeases).toHaveBeenCalledTimes(1);
    expect(ordinaryRestores).not.toHaveBeenCalled();
    expect(connections).not.toHaveBeenCalled();
  });

  it("discloses the full app grant before fresh approval when the node refuses the lease", async () => {
    const prefix = await runnerSessionPrefix(APP_ID);
    seedSession(prefix, openManifest(firstVersion.manifest));
    renewalStopped = true;
    chooseRenewal = false;
    vi.setSystemTime(SIGNED_END + 1);
    const disclose = vi.fn();

    const { session } = await open(firstVersion.entry, [firstVersion.entry], (progress) => {
      if (progress.phase === "disclosing") disclose(progress.manifest);
    });

    expect(restoredLeases).toHaveBeenCalledTimes(1);
    expect(ordinaryRestores).not.toHaveBeenCalled();
    expect(connections).toHaveBeenCalledTimes(1);
    const connection = connections.mock.invocationCallOrder[0]!;
    expect(disclose).toHaveBeenCalledWith(firstVersion.manifest);
    expect(disclose.mock.invocationCallOrder[0]).toBeLessThan(connection);
    expect(restoredLeases.mock.invocationCallOrder[0]).toBeLessThan(connection);
    expect(authorizations).toHaveLength(1);
    const request = authorizations[0]!;
    expect(request.renewal).toEqual({ version: 1, leaseLifetimeSeconds: 90 * 86_400, purpose: "standing" });
    expect(sdk.extractRecapAttenuations(request.siwe)).toMatchObject({
      [`tinycloud:applications/kv/${APP_ID}/app/`]: { "tinycloud.kv/get": [{}], "tinycloud.kv/list": [{}], "tinycloud.kv/put": [{}] },
      [`tinycloud:applications/kv/${APP_ID}/records/`]: { "tinycloud.kv/get": [{}], "tinycloud.kv/put": [{}] },
      [`tinycloud:applications/kv/${APP_ID}/knowledge/`]: { "tinycloud.kv/put": [{}] },
    });
    expect(stepUps).not.toHaveBeenCalled();
    expect(await session.data.kvGet(RECORD)).toMatchObject({ ok: true });
    expect(loadRenewalReceipt(prefix, OWNER.address)).toBeNull();
  });

  it("keeps the runtime open past the signed end through the node's effective expiry", async () => {
    seedSession(await runnerSessionPrefix(APP_ID), openManifest(firstVersion.manifest));
    vi.setSystemTime(SIGNED_END + 1);
    expect((await open()).session.expiresAt).toBe(RENEWED_END - 60_000);
  });

  it("uses the signed end if the runner cannot read the node's effective expiry", async () => {
    seedSession(await runnerSessionPrefix(APP_ID), openManifest(firstVersion.manifest));
    vi.setSystemTime(SIGNED_END + 1);
    expiryUnavailable = true;

    expect((await open()).session.expiresAt).toBe(SIGNED_END - 60_000);
    expect(restoredLeases).toHaveBeenCalledTimes(1);
  });

  it("opens OpenKey again after the signed end when the owner chose a finite session", async () => {
    chooseRenewal = false;
    const { session } = await open();
    const prefix = await runnerSessionPrefix(APP_ID);
    const signedEnd = saved.get(prefix)!.expiresAt;
    expect(loadRenewalReceipt(prefix, OWNER.address)).toBeNull();
    await session.detach();
    vi.setSystemTime(signedEnd + 1);

    expect(await createRunPorts().hasPersistedSession?.(APP_ID)).toBe(false);
    const reopened = await open();
    expect(connections).toHaveBeenCalledTimes(2);
    expect(authorizations.length + legacyApprovals.mock.calls.length).toBe(2);
    expect(restoredLeases).not.toHaveBeenCalled();
    expect(reopened.session.expiresAt).toBeGreaterThan(Date.now());
  });

  it("asks only for the newly installed version's uncovered grant and ignores kept grants for the old digest", async () => {
    const prefix = await runnerSessionPrefix(APP_ID);
    seedSession(prefix, openManifest(firstVersion.manifest));
    const settings = { service: "tinycloud.kv", space: "applications", path: `${APP_ID}/settings/`, actions: ["tinycloud.kv/get", "tinycloud.kv/put"] };
    localStorage.setItem(`${prefix}-runtime-grants`, JSON.stringify({
      version: 1, appId: APP_ID, digest: firstVersion.entry.bundle.digest,
      ownerAddress: OWNER.address, delegations: [JSON.stringify(settings)],
    }));
    install(nextVersion);
    vi.setSystemTime(SIGNED_END + 1);

    const { app } = await open(firstVersion.entry, [firstVersion.entry, nextVersion.entry]);

    expect(restoredLeases).toHaveBeenCalledTimes(1);
    expect(reusedGrants).not.toHaveBeenCalled();
    expect(stepUps).toHaveBeenCalledExactlyOnceWith([settings]);
    expect(app.entry.bundle.digest).toBe(nextVersion.entry.bundle.digest);
  });

  it.each([
    { name: "a wider path", edit: { permissions: [{ service: "tinycloud.kv", path: "elsewhere/", actions: ["get"] }] }, reason: "widened" },
    { name: "secrets", edit: { secrets: { TOKEN: true } }, reason: "unsupported" },
    { name: "another space", edit: { space: "elsewhere" }, reason: "unsupported" },
    { name: "another service", edit: { permissions: [{ service: "tinycloud.duckdb", path: "warehouse", actions: ["read"] }] }, reason: "unsupported" },
  ])("refuses a saved manifest asking for $name on a lease restore", async ({ edit, reason }) => {
    const prefix = await runnerSessionPrefix(APP_ID);
    seedSession(prefix, openManifest(firstVersion.manifest));
    files.set(`${APP_ID}/app/manifest.json`, JSON.stringify({ ...firstVersion.manifest, ...edit }));
    vi.setSystemTime(SIGNED_END + 1);

    await expect(open()).rejects.toMatchObject({ reason });
    expect(restoredLeases).toHaveBeenCalledTimes(1);
    expect(authorizations).toEqual([]);
    expect(stepUps).not.toHaveBeenCalled();
  });

  it("keeps the receipt on a narrow reopen and detach, then clears it on explicit sign-out", async () => {
    const prefix = await runnerSessionPrefix(APP_ID);
    seedSession(prefix, openManifest(firstVersion.manifest));

    const { session } = await open();
    expect(ordinaryRestores).toHaveBeenCalledTimes(1);
    expect(versionedSignIns).toHaveBeenCalledExactlyOnceWith(true);
    expect(connections).not.toHaveBeenCalled();
    expect(authorizations).toEqual([]);
    await session.detach();
    expect(localStorage.getItem(activeKey(prefix))).toBe(OWNER.address);
    expect(loadRenewalReceipt(prefix, OWNER.address)).toEqual(lease(prefix, OWNER.address));

    await (await open()).session.end();

    expect(loadRenewalReceipt(prefix, OWNER.address)).toBeNull();
    expect(await createRunPorts().hasPersistedSession?.(APP_ID)).toBe(false);
  });

  it("does not use the first app's lease to open another app", async () => {
    const prefix = await runnerSessionPrefix(APP_ID);
    seedSession(prefix, openManifest(firstVersion.manifest));
    vi.setSystemTime(SIGNED_END + 1);

    await open(otherApp.entry);

    expect(restoredLeases).not.toHaveBeenCalled();
    expect(connections).toHaveBeenCalledTimes(1);
    expect(loadRenewalReceipt(prefix, OWNER.address)).toEqual(lease(prefix, OWNER.address));
  });

  it("does not use one account's receipt with another account's saved grant", async () => {
    seedSession(await runnerSessionPrefix(APP_ID), openManifest(firstVersion.manifest), true, OTHER_ADDRESS);
    vi.setSystemTime(SIGNED_END + 1);

    await open();

    expect(restoredLeases).not.toHaveBeenCalled();
    expect(connections).toHaveBeenCalledTimes(1);
  });

  it("asks for fresh approval when the lease has expired", async () => {
    const prefix = await runnerSessionPrefix(APP_ID);
    seedSession(prefix, openManifest(firstVersion.manifest));
    chooseRenewal = false;
    vi.setSystemTime(LEASE_END + 1);

    const reopened = await open();

    expect(connections).toHaveBeenCalledTimes(1);
    expect(reopened.session.expiresAt).toBeGreaterThan(Date.now());
    expect(loadRenewalReceipt(prefix, OWNER.address)).toBeNull();
  });

  it("owner stop keeps the original signed session usable until its end and requires approval after it", async () => {
    const prefix = await runnerSessionPrefix(APP_ID);
    seedSession(prefix, openManifest(firstVersion.manifest));
    renewalStopped = true;
    const { session } = await open();
    expect(await session.data.kvGet(RECORD)).toMatchObject({ ok: true });
    expect(connections).not.toHaveBeenCalled();
    expect(restoredLeases).not.toHaveBeenCalled();
    await session.detach();
    vi.setSystemTime(SIGNED_END + 1);
    refuseApproval = true;

    expect(await session.data.kvGet(RECORD)).toMatchObject({ ok: false });
    await expect(open()).rejects.toMatchObject({ reason: "cancelled" });
    expect(restoredLeases).toHaveBeenCalledTimes(1);
    expect(connections).toHaveBeenCalledTimes(1);
    expect(loadRenewalReceipt(prefix, OWNER.address)).toBeNull();
  });
});

describe("runner view expiry", () => {
  it.each([
    { renewing: true, title: "Your session ended", copy: "Reopen the app to carry on." },
    { renewing: false, title: "Your session expired", copy: "Your session expired: open the app again." },
  ])("shows $title and uses the session's expiry behavior", async ({ renewing, title, copy }) => {
    vi.useRealTimers();
    vi.useFakeTimers({ now: SIGNED_END - 65_000, toFake: ["setTimeout", "clearTimeout", "Date"], shouldAdvanceTime: true });
    const prefix = await runnerSessionPrefix(APP_ID);
    seedSession(prefix, openManifest(firstVersion.manifest), renewing);
    const ports = createRunPorts();
    const end = vi.fn();
    const detach = vi.fn();
    const root = document.body.appendChild(document.createElement("div"));
    const runner = mountRunner(root, {
      appId: APP_ID,
      ports: {
        ...ports,
        catalog: [firstVersion.entry],
        async signIn(...args) {
          const session = await ports.signIn(...args);
          return {
            ...session,
            runtime: {
              ...session.runtime,
              end: async () => { end(); await session.runtime.end(); },
              detach: async () => { detach(); await session.runtime.detach(); },
            },
          };
        },
      },
    });
    try {
      await vi.waitFor(() => expect(root.querySelector("iframe")).not.toBeNull());
      await vi.advanceTimersByTimeAsync(5_001);

      expect(root.querySelector("iframe")).toBeNull();
      expect(root.querySelector(".run-screen__title")?.textContent).toBe(title);
      expect(root.textContent).toContain(copy);
      expect(end).toHaveBeenCalledTimes(renewing ? 0 : 1);
      expect(detach).toHaveBeenCalledTimes(renewing ? 1 : 0);
      expect(localStorage.getItem(activeKey(prefix))).toBe(renewing ? OWNER.address : null);
      expect(loadRenewalReceipt(prefix, OWNER.address)).toEqual(renewing ? lease(prefix, OWNER.address) : null);
      if (!renewing) return;

      vi.setSystemTime(SIGNED_END + 1);
      const reopen = [...root.querySelectorAll("button")].find((button) => button.textContent === "Open Test app again");
      expect(reopen).toBeDefined();
      reopen!.click();

      await vi.waitFor(() => expect(root.querySelector("iframe")).not.toBeNull());
      expect(restoredLeases).toHaveBeenCalledTimes(1);
      expect(connections).not.toHaveBeenCalled();
      expect(authorizations).toEqual([]);
    } finally {
      runner.destroy();
      root.remove();
    }
  });
});

describe("shared sign-in with library renewal options", () => {
  const signIn = () => signInWithManifest({
    manifest: shareManifest, ...SHARE_MANIFEST_SCOPE, config: CONFIG, sessionPrefix: LIBRARY_SESSION_PREFIX,
    versionedSignIn: true, persistSession: true, renewal: true, restoreBeforeOpenKey: true,
  });

  function seedLibrary(receipt: boolean) {
    seedSession(LIBRARY_SESSION_PREFIX, shareManifest, receipt);
    localStorage.setItem(`${LIBRARY_SESSION_PREFIX}openkey-account`, JSON.stringify({
      address: OWNER.address, keyId: "test-key", keyType: "MANAGED",
    }));
    vi.setSystemTime(SIGNED_END + 1);
  }

  it("keeps the library's saved account pointer past the signed end while the receipt runs", async () => {
    seedLibrary(true);
    expect(savedLibraryAccount()?.address).toBe(OWNER.address);

    await signIn();

    expect(localStorage.getItem(activeKey(LIBRARY_SESSION_PREFIX))).toBe(OWNER.address);
    expect(saved.get(LIBRARY_SESSION_PREFIX)?.expiresAt).toBe(SIGNED_END);
  });

  it("restores the library through the lease without opening OpenKey", async () => {
    seedLibrary(true);

    await signIn();

    expect(restoredLeases).toHaveBeenCalledTimes(1);
    expect(ordinaryRestores).not.toHaveBeenCalled();
    expect(connections).not.toHaveBeenCalled();
  });

  it("opens OpenKey after the signed end when the library has no receipt", async () => {
    seedLibrary(false);
    chooseRenewal = false;
    expect(savedLibraryAccount()).toBeUndefined();

    await signIn();

    expect(restoredLeases).not.toHaveBeenCalled();
    expect(connections).toHaveBeenCalledTimes(1);
  });

  it("reports the node's effective renewal expiry in milliseconds", async () => {
    seedLibrary(true);
    expect((await signIn()).sessionExpiresAt).toBe(RENEWED_END);
  });

  it("uses the signed end if the node's effective expiry cannot be read", async () => {
    seedLibrary(true);
    expiryUnavailable = true;

    expect((await signIn()).sessionExpiresAt).toBe(SIGNED_END);
    expect(restoredLeases).toHaveBeenCalledTimes(1);
    expect(connections).not.toHaveBeenCalled();
  });
});
