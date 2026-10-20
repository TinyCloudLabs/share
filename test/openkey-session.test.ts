// @vitest-environment jsdom
import { beforeEach, describe, expect, it, vi } from "vitest";
import { privateKeyToAccount } from "viem/accounts";
import { composeManifestRequest, type CallbackStrategy } from "@tinycloud/sdk-core";
import type { Manifest, PermissionEntry } from "@tinycloud/web-sdk";
import {
  authenticateWithOpenKey,
  createTinyCloudClient,
  filesForYouPermissions,
  MAX_SESSION_MS,
  ObservedOpenKeyProvider,
  ownerEncryptionNetwork,
  SAVE_COPY_APP_ID,
  SAVE_COPY_MANIFEST_SCOPE,
  saveCopyManifest,
  SHARE_MANIFEST_SCOPE,
  shareManifest,
  SignInOptionError,
  signInWithManifest,
  type ApprovalGuard,
} from "../src/share/openkey-session.js";
import { ManifestRejectedError, SDK_ACCOUNT_REGISTRY_RESOURCES, type ManifestScope } from "../src/share/manifest-policy.js";
import { resetRevokeFlights, withWalletApproval } from "../src/share/revoke-flight.js";

const state = vi.hoisted(() => ({
  config: undefined as Record<string, unknown> | undefined,
  clients: [] as Array<{ config: Record<string, unknown>; hosted: string[]; order: string[]; signedOut: number }>,
  // OpenKey instances made, their app names, how many times each flow was closed, and whether connect fails.
  openKeys: [] as Array<{ appName: unknown; disconnects: number }>,
  connectError: undefined as unknown,
  onConnect: undefined as undefined | (() => void),
  constructorError: undefined as unknown,
  hostError: undefined as unknown,
  hangSign: false,
  signInError: undefined as unknown,
  registrySync: undefined as undefined | { promise: Promise<unknown> },
  signed: [] as Array<{ message: string; keyId?: string }>,
  // Who actually signs, and whether the widget answers with a signature at all.
  signer: undefined as { signMessage(input: { message: string }): Promise<string> } | undefined,
  omitSignature: false,
  sender: "",
  providerSignature: "",
}));

const SENDER = privateKeyToAccount("0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d");
const OTHER = privateKeyToAccount("0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a");
state.sender = SENDER.address;

// Production OpenKey since TC-688: connect() answers without a session token
// and getSessionToken() is always null for embedding pages. The widget always
// reports the connected address, whoever signed.
vi.mock("@openkey/sdk", () => ({
  OpenKey: class {
    private readonly record: { appName: unknown; disconnects: number };
    constructor(config?: { appName?: unknown }) { this.record = { appName: config?.appName, disconnects: 0 }; state.openKeys.push(this.record); }
    disconnect() { this.record.disconnects += 1; }
    async connect() { state.onConnect?.(); if (state.connectError !== undefined) throw state.connectError; return { address: state.sender, keyId: "key-1", keyType: "MANAGED" }; }
    getSessionToken() { return null; }
    tinycloudSigningOptions() { return { endpoint: "https://api.openkey.so/api/delegate/sign", token: null }; }
    async signMessage(request: { message: string; keyId?: string }) {
      if (state.hangSign) return new Promise<never>(() => undefined);
      state.signed.push(request);
      const signature = state.omitSignature ? undefined : await state.signer!.signMessage({ message: request.message });
      return { address: state.sender, signature };
    }
  },
  OpenKeyProvider: class { async request(): Promise<string> { return state.providerSignature; } },
}));

vi.mock("@tinycloud/web-sdk", () => ({
  TinyCloudWeb: class {
    private readonly record: { config: Record<string, unknown>; hosted: string[]; order: string[]; signedOut: number };
    get pendingAccountRegistrySync() { return state.registrySync; }
    constructor(config: Record<string, unknown>) {
      if (state.constructorError !== undefined) throw state.constructorError;
      state.config = config;
      this.record = { config, hosted: [], order: [], signedOut: 0 };
      state.clients.push(this.record);
    }
    async signIn(): Promise<void> { this.record.order.push("signIn"); if (state.signInError !== undefined) throw state.signInError; }
    async signOut(): Promise<void> { this.record.signedOut += 1; }
    async ensureOwnedSpaceHosted(name: string): Promise<string> { if (state.hostError !== undefined) throw state.hostError; this.record.hosted.push(name); this.record.order.push(`host:${name}`); return name === "account" ? "account" : `space-of-${name}`; }
  },
}));

const CONFIG = {
  shareOrigin: "https://share.tinycloud.xyz",
  senderBootstrapNodeOrigin: "https://tee.node.tinycloud.xyz",
  registryOrigin: "https://registry.tinycloud.xyz",
} as never;

async function signedInStrategy(): Promise<CallbackStrategy> {
  const session = await authenticateWithOpenKey(() => undefined);
  await createTinyCloudClient(session, CONFIG, () => undefined);
  return state.config?.signStrategy as CallbackStrategy;
}

describe("Share signing through the OpenKey widget (TC-994)", () => {
  beforeEach(() => {
    state.config = undefined;
    state.signed = [];
    state.signer = SENDER;
    state.omitSignature = false;
    vi.stubGlobal("fetch", vi.fn(() => Promise.reject(new Error("Share must not call OpenKey's signer directly"))));
  });

  it("signs in when OpenKey gives the page no session token", async () => {
    await expect(authenticateWithOpenKey(() => undefined)).resolves.toMatchObject({ address: SENDER.address });
  });

  it("asks the sender's OpenKey widget for sign-in, bootstrap and hosting signatures", async () => {
    const strategy = await signedInStrategy();
    const purposes = ["sign-in", "bootstrap-session", "bootstrap-host"] as const;
    for (const purpose of purposes) {
      const message = `siwe:${purpose}`;
      await expect(strategy.handler({ address: SENDER.address, chainId: 1, message, type: "siwe", purpose }))
        .resolves.toEqual({ approved: true, signature: await SENDER.signMessage({ message }) });
    }
    expect(state.signed).toEqual(purposes.map((purpose) => ({ message: `siwe:${purpose}`, keyId: "key-1" })));
    expect(fetch).not.toHaveBeenCalled();
  });

  it("refuses a signature from another account even when OpenKey reports the sender's address", async () => {
    const strategy = await signedInStrategy();
    state.signer = OTHER;
    await expect(strategy.handler({ address: SENDER.address, chainId: 1, message: "siwe:host", type: "siwe", purpose: "bootstrap-host" }))
      .resolves.toMatchObject({ approved: false });
  });

  it("refuses an approval that carries no signature", async () => {
    const strategy = await signedInStrategy();
    state.omitSignature = true;
    await expect(strategy.handler({ address: SENDER.address, chainId: 1, message: "credential", type: "message", purpose: "message" }))
      .resolves.toMatchObject({ approved: false });
  });
});

describe("signInWithManifest: one sign-in, any manifest inside its scope", () => {
  beforeEach(() => {
    state.config = undefined;
    state.clients.length = 0;
    state.openKeys.length = 0;
    state.connectError = undefined;
    state.onConnect = undefined;
    state.constructorError = undefined;
    state.hostError = undefined;
    state.signInError = undefined;
    state.registrySync = undefined;
    state.signed = [];
    state.signer = SENDER;
    state.omitSignature = false;
    localStorage.clear();
    sessionStorage.clear();
  });

  const APP_MANIFEST: Manifest = {
    manifest_version: 1,
    app_id: "xyz.example.notes",
    name: "Notes",
    space: "applications",
    prefix: "xyz.example.notes/",
    defaults: false,
    includePublicSpace: false,
    permissions: [{ service: "tinycloud.kv", space: "applications", path: "xyz.example.notes/data/", actions: ["get", "put"], skipPrefix: true }],
  };
  const manifestOf = (index: number): Manifest => state.clients[index]!.config.manifest as Manifest;

  it("signs in with the manifest it is given: Share's library, the viewer's save and an app are three different sessions", async () => {
    const library = await signInWithManifest({ manifest: shareManifest, ...SHARE_MANIFEST_SCOPE, config: CONFIG });
    const save = await signInWithManifest({ manifest: saveCopyManifest(), ...SAVE_COPY_MANIFEST_SCOPE, config: CONFIG });
    const app = await signInWithManifest({ manifest: APP_MANIFEST, config: CONFIG });

    expect(state.clients).toHaveLength(3);
    expect(manifestOf(0).permissions).toContainEqual(expect.objectContaining({ service: "tinycloud.encryption" }));
    expect(manifestOf(0).permissions).toEqual(shareManifest(SENDER.address).permissions);
    // The viewer's manifest asks for the private copies area and nothing else.
    expect(manifestOf(1).permissions).toEqual(filesForYouPermissions());
    expect(manifestOf(1).permissions!.map((entry) => entry.service)).toEqual(["tinycloud.kv"]);
    expect(manifestOf(2)).toEqual(APP_MANIFEST);
    expect(new Set([library.tinycloud, save.tinycloud, app.tinycloud]).size).toBe(3);
    for (const signedIn of [library, save, app]) expect(signedIn.session.address).toBe(SENDER.address);
  });

  it("the library and Save register under different app ids, so an account using both never has one overwrite the other's registry record", async () => {
    await signInWithManifest({ manifest: shareManifest, ...SHARE_MANIFEST_SCOPE, config: CONFIG });
    await signInWithManifest({ manifest: saveCopyManifest(), ...SAVE_COPY_MANIFEST_SCOPE, config: CONFIG });
    await signInWithManifest({ manifest: shareManifest, ...SHARE_MANIFEST_SCOPE, config: CONFIG });
    const ids = state.clients.map((_client, index) => manifestOf(index).app_id);
    expect(ids).toEqual(["xyz.tinycloud.share", SAVE_COPY_APP_ID, "xyz.tinycloud.share"]);
    expect(SAVE_COPY_APP_ID).not.toBe("xyz.tinycloud.share");
    // The SDK keys the registry record by app id: the library's record is only ever written with the library's manifest.
    expect(manifestOf(0)).toEqual(manifestOf(2));
    expect(manifestOf(1).permissions).not.toEqual(manifestOf(0).permissions);
  });

  it("gives a manifest function the connected address (after checking its shape with a placeholder first)", async () => {
    const seen: string[] = [];
    await signInWithManifest({ manifest: (address) => { seen.push(address); return APP_MANIFEST; }, config: CONFIG });
    expect(seen).toEqual(["0x0000000000000000000000000000000000000000", SENDER.address]);
    expect(shareManifest(SENDER.address).permissions).toContainEqual(expect.objectContaining({ path: ownerEncryptionNetwork(SENDER.address) }));
  });

  it("hosts the account space first, then each named space once, and returns the ids", async () => {
    const { spaces } = await signInWithManifest({ manifest: saveCopyManifest(), ...SAVE_COPY_MANIFEST_SCOPE, config: CONFIG, hostSpaces: ["files-for-you", "account", "files-for-you"] });
    expect(state.clients[0]!.order).toEqual(["signIn", "host:account", "host:files-for-you"]);
    expect(spaces).toEqual({ account: "account", "files-for-you": "space-of-files-for-you" });
  });

  it("refuses to host a space the manifest may not use, before OpenKey opens", async () => {
    await expect(signInWithManifest({ manifest: saveCopyManifest(), ...SAVE_COPY_MANIFEST_SCOPE, config: CONFIG, hostSpaces: ["secrets"] }))
      .rejects.toMatchObject({ name: "ManifestRejectedError", code: "space-not-allowed" });
    expect(state.openKeys).toEqual([]);
    expect(state.clients).toEqual([]);
  });

  it("keeps the session in memory: nothing is persisted, and no storage is written", async () => {
    await signInWithManifest({ manifest: saveCopyManifest(), ...SAVE_COPY_MANIFEST_SCOPE, config: CONFIG, hostSpaces: ["files-for-you"] });
    expect(state.clients[0]!.config.persistSession).toBe(false);
    expect(localStorage.length).toBe(0);
    expect(sessionStorage.length).toBe(0);
  });

  it("reuses an OpenKey connection that already exists instead of opening OpenKey again", async () => {
    const session = await authenticateWithOpenKey(() => undefined);
    const before = state.openKeys.length;
    const { session: used } = await signInWithManifest({ manifest: saveCopyManifest(), ...SAVE_COPY_MANIFEST_SCOPE, config: CONFIG, session });
    expect(used).toBe(session);
    expect(state.openKeys).toHaveLength(before);
  });

  it("makes every OpenKey wait go through the guard, saying what it is: connect, and each signature with its purpose", async () => {
    const waits: Array<[string, string | undefined]> = [];
    const guardApproval: ApprovalGuard = async (wait, info) => { waits.push([info?.kind ?? "none", info?.purpose]); return wait(); };
    await signInWithManifest({ manifest: saveCopyManifest(), ...SAVE_COPY_MANIFEST_SCOPE, config: CONFIG, guardApproval });
    expect(waits).toEqual([["connect", undefined]]);
    const strategy = state.config?.signStrategy as CallbackStrategy;
    await strategy.handler({ address: SENDER.address, chainId: 1, message: "siwe:sign-in", type: "siwe", purpose: "sign-in" });
    expect(waits).toEqual([["connect", undefined], ["sign", "sign-in"]]);
  });


  it("closes the OpenKey flow when a wait ends in an error: a cancel, a refusal, the guard giving up", async () => {
    const session = await authenticateWithOpenKey(() => undefined);
    const closedBefore = state.openKeys[0]!.disconnects;
    const guardApproval: ApprovalGuard = async (wait) => { void wait().catch(() => undefined); throw new Error("revoke-approval-abandoned"); };
    await signInWithManifest({ manifest: saveCopyManifest(), ...SAVE_COPY_MANIFEST_SCOPE, config: CONFIG, session, guardApproval });
    const strategy = state.config?.signStrategy as CallbackStrategy;
    await expect(strategy.handler({ address: SENDER.address, chainId: 1, message: "siwe:sign-in", type: "siwe", purpose: "sign-in" })).rejects.toThrow("revoke-approval-abandoned");
    expect(state.openKeys[0]!.disconnects).toBe(closedBefore + 1);
  });

  it("an approval nobody answers is given up after 60 seconds: the OpenKey window is closed and the next approval may ask again", async () => {
    vi.useFakeTimers();
    resetRevokeFlights();
    try {
      const guardApproval: ApprovalGuard = (wait) => withWalletApproval({ setApproval: () => undefined }, () => wait());
      const session = await authenticateWithOpenKey(() => undefined);
      const closedBefore = state.openKeys[0]!.disconnects;
      await signInWithManifest({ manifest: saveCopyManifest(), ...SAVE_COPY_MANIFEST_SCOPE, config: CONFIG, session, guardApproval });
      const strategy = state.config?.signStrategy as CallbackStrategy;
      state.hangSign = true;
      const waiting = strategy.handler({ address: SENDER.address, chainId: 1, message: "siwe:sign-in", type: "siwe", purpose: "sign-in" }).catch((error: unknown) => error);
      await vi.advanceTimersByTimeAsync(59_000);
      expect(state.openKeys[0]!.disconnects).toBe(closedBefore);
      await vi.advanceTimersByTimeAsync(1_000);
      expect(((await waiting) as Error).message).toBe("revoke-approval-abandoned");
      expect(state.openKeys[0]!.disconnects).toBe(closedBefore + 1);
      // The lock is free: a new approval is asked, not refused as "another approval".
      state.hangSign = false;
      await expect(strategy.handler({ address: SENDER.address, chainId: 1, message: "siwe:again", type: "siwe", purpose: "sign-in" })).resolves.toMatchObject({ approved: true });
    } finally {
      state.hangSign = false;
      vi.useRealTimers();
      resetRevokeFlights();
    }
  });

  it("a connect that is cancelled or given up leaves no window behind", async () => {
    state.connectError = { code: "USER_CANCELLED" };
    await expect(signInWithManifest({ manifest: saveCopyManifest(), ...SAVE_COPY_MANIFEST_SCOPE, config: CONFIG })).rejects.toMatchObject({ code: "USER_CANCELLED" });
    expect(state.openKeys[0]!.disconnects).toBe(1);
    expect(state.clients).toEqual([]);
  });

  it("hands the client out before sign-in so a failed approval can still be read", async () => {
    let stepsWhenHandedOut: string[] | undefined;
    await signInWithManifest({ manifest: saveCopyManifest(), ...SAVE_COPY_MANIFEST_SCOPE, config: CONFIG, onClient: () => { stepsWhenHandedOut = [...state.clients[0]!.order]; } });
    expect(stepsWhenHandedOut).toEqual([]);
  });
});

describe("signInWithManifest refuses a manifest outside its scope: nothing signed, OpenKey never opened", () => {
  beforeEach(() => {
    state.clients.length = 0;
    state.openKeys.length = 0;
    state.connectError = undefined;
    state.onConnect = undefined;
    state.constructorError = undefined;
    state.hostError = undefined;
    state.signInError = undefined;
  });

  /** An app manifest; `omit` leaves a field out altogether (the SDK's own defaults then apply). */
  const app = (permissions: PermissionEntry[], extra: Partial<Manifest> = {}, omit: ReadonlyArray<keyof Manifest> = []): Manifest => {
    const manifest: Manifest = { manifest_version: 1, app_id: "xyz.example.notes", name: "Notes", space: "applications", prefix: "xyz.example.notes/", defaults: false, includePublicSpace: false, permissions, ...extra };
    for (const key of omit) delete manifest[key];
    return manifest;
  };
  const kv = (path: string, actions: string[], extra: Record<string, unknown> = {}) => ({ service: "tinycloud.kv", space: "applications", path, actions, skipPrefix: true, ...extra });
  const inside = "xyz.example.notes/data/";

  async function refused(manifest: Manifest, code: string, scope: ManifestScope & { unsafeAllowBroadManifest?: boolean } = {}): Promise<void> {
    state.openKeys.length = 0;
    state.clients.length = 0;
    await expect(signInWithManifest({ manifest, config: CONFIG, ...scope })).rejects.toMatchObject({ name: "ManifestRejectedError", code });
    await expect(signInWithManifest({ manifest, config: CONFIG, ...scope })).rejects.toBeInstanceOf(ManifestRejectedError);
    expect(state.openKeys, "OpenKey must not be opened").toEqual([]);
    expect(state.clients, "no session may be made").toEqual([]);
  }

  it.each([
    ["delegation abilities (a wildcard over delegation, the thing that passes a grant on)", app([{ service: "tinycloud.delegation", space: "default", path: "/", actions: ["*"], skipPrefix: true }]), "delegation-ability"],
    ["a named delegation ability", app([{ service: "tinycloud.delegation", space: "applications", path: inside, actions: ["create"], skipPrefix: true }]), "delegation-ability"],
    ["a wildcard service", app([{ service: "*", space: "applications", path: inside, actions: ["get"], skipPrefix: true }]), "wildcard"],
    ["a wildcard action", app([kv(inside, ["*"])]), "wildcard"],
    ["another space", app([kv(inside, ["get"], { space: "default" })]), "space-not-allowed"],
    ["a space named by its full URI", app([kv(inside, ["get"], { space: `tinycloud:pkh:eip155:1:${SENDER.address}:default` })]), "space-not-allowed"],
    ["the secrets space through the secrets shorthand", app([kv(inside, ["get"])], { secrets: { TOKEN: true } }), "space-not-allowed"],
    ["the whole space", app([kv("/", ["get"])]), "path-not-allowed"],
    ["a path outside the manifest's own prefix", app([kv("other/", ["get"])]), "path-not-allowed"],
    ["a sibling prefix that only starts the same", app([kv("xyz.example.notes-evil/", ["get"])]), "path-not-allowed"],
    ["delete, which must be named", app([kv(inside, ["get", "del"])]), "action-not-allowed"],
    ["sql schema, which must be named", app([{ service: "tinycloud.sql", space: "applications", path: `${inside}db`, actions: ["schema"], skipPrefix: true }]), "action-not-allowed"],
    ["a service that is not allowed", app([{ service: "tinycloud.duckdb", space: "applications", path: `${inside}db`, actions: ["read"], skipPrefix: true }]), "service-not-allowed"],
    ["defaults left on: the SDK would add a standard grant over the whole space", app([kv(inside, ["get"])], {}, ["defaults"]), "action-not-allowed"],
    ["the public space companion left on", app([kv(inside, ["get"])], {}, ["includePublicSpace"]), "public-space"],
    ["a delegate DID", app([kv(inside, ["get"])], { did: "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK" }), "delegate-target"],
    ["a manifest the SDK itself cannot read", { name: "No app id" } as unknown as Manifest, "invalid-manifest"],
  ])("%s", async (_label, manifest, code) => {
    await refused(manifest, code);
  });

  it("an app manifest with an empty prefix must say where it may write", async () => {
    await refused(app([kv(inside, ["get"])], { prefix: "" }), "path-not-allowed");
    await expect(signInWithManifest({ manifest: app([kv(inside, ["get"])], { prefix: "" }), config: CONFIG, allowedPathPrefixes: [inside] })).resolves.toBeDefined();
  });

  it("the library's manifest is refused under Save's scope, and Save's under the library's wrong space list", async () => {
    await refused(shareManifest(SENDER.address), "action-not-allowed", SAVE_COPY_MANIFEST_SCOPE);
    await refused(saveCopyManifest(), "space-not-allowed", { allowedSpaces: ["applications"], allowedServices: ["kv"], allowedActions: ["get", "put", "list"], allowedPathPrefixes: ["v1/"] });
  });

  it("a broader scope has to be stated by name: delete is allowed only when allowedActions says so", async () => {
    const manifest = app([kv(inside, ["get", "del"])]);
    await refused(manifest, "action-not-allowed");
    await expect(signInWithManifest({ manifest, config: CONFIG, allowedActions: ["get", "del"] })).resolves.toBeDefined();
  });

  it("a manifest function that is fine for the placeholder but broad for the real account is refused after OpenKey connects and before anything is signed", async () => {
    const manifest = (address: string): Manifest => app(address === "0x0000000000000000000000000000000000000000" ? [kv(inside, ["get"])] : [kv("/", ["get"])]);
    await expect(signInWithManifest({ manifest, config: CONFIG })).rejects.toMatchObject({ code: "path-not-allowed" });
    expect(state.openKeys).toHaveLength(1);
    expect(state.clients).toEqual([]);
    // The connection this call opened is closed again; nothing is left open behind a refusal.
    expect(state.openKeys[0]!.disconnects).toBe(1);
  });

  it("a function manifest that throws, or a refusal on a connection the CALLER opened, leaves the caller's connection alone", async () => {
    const broad = (address: string): Manifest => app(address === "0x0000000000000000000000000000000000000000" ? [kv(inside, ["get"])] : [kv("/", ["get"])]);
    const session = await authenticateWithOpenKey(() => undefined);
    await expect(signInWithManifest({ manifest: broad, config: CONFIG, session })).rejects.toMatchObject({ code: "path-not-allowed" });
    expect(state.openKeys[0]!.disconnects).toBe(0);
    state.openKeys.length = 0;
    const exploding = (address: string): Manifest => { if (address !== "0x0000000000000000000000000000000000000000") throw new Error("catalog failed"); return app([kv(inside, ["get"])]); };
    await expect(signInWithManifest({ manifest: exploding, config: CONFIG })).rejects.toThrow("catalog failed");
    expect(state.openKeys[0]!.disconnects).toBe(1);
    expect(state.clients).toEqual([]);
  });

  // N1: the SDK adds a capability-list read for every space a manifest names; a manifest must not add one for a space it may not use.
  it.each([
    ["default", "default"], ["secrets", "secrets"], ["the public space", "public"], ["a space named by URI", `tinycloud:pkh:eip155:1:${SENDER.address}:default`],
  ])("refuses a capabilities read on %s", async (_label, space) => {
    await refused(app([{ service: "tinycloud.capabilities", space, path: "", actions: ["read"] }]), "space-not-allowed");
  });

  it("refuses a delegation list on any space, and a capabilities entry that is more than a bare read", async () => {
    for (const space of ["applications", "default", "secrets"]) {
      await refused(app([{ service: "tinycloud.delegation", space, path: "", actions: ["list"] }]), "delegation-ability");
    }
    await refused(app([{ service: "tinycloud.capabilities", space: "applications", path: "", actions: ["write"] }]), "action-not-allowed");
    await refused(app([{ service: "tinycloud.capabilities", space: "applications", path: "some/key", actions: ["read"] }]), "path-not-allowed");
  });

  it("a delegation list is allowed only when the scope names it, and then only in the spaces the scope names", async () => {
    const scope = { allowedServices: ["kv", "delegation"], allowedActions: ["get", "tinycloud.delegation/list"], allowedSpaces: ["applications"] };
    const listing = (space: string): Manifest => app([kv(inside, ["get"]), { service: "tinycloud.delegation", space, path: "", actions: ["list"], skipPrefix: true }]);
    await expect(signInWithManifest({ manifest: listing("applications"), config: CONFIG, ...scope })).resolves.toBeDefined();
    await refused(listing("default"), "space-not-allowed", scope);
    // Naming the service alone, or a bare action, is not enough.
    await refused(listing("applications"), "delegation-ability", { allowedServices: ["kv", "delegation"], allowedActions: ["get", "list"] });
    await refused(listing("applications"), "delegation-ability", { allowedActions: ["get", "tinycloud.delegation/list"] });
  });

  // N2: an ability belongs to its own service, whatever resource carries it.
  it.each([
    ["a delegation ability on a kv resource", kv(inside, ["tinycloud.delegation/list"]), "delegation-ability"],
    ["a delegation ability, cased differently", kv(inside, ["Tinycloud.Delegation/list"]), "delegation-ability"],
    ["a delegation ability on a capabilities resource", { service: "tinycloud.capabilities", space: "applications", path: "", actions: ["tinycloud.delegation/read"] }, "delegation-ability"],
    ["a capabilities ability on a kv resource", kv(inside, ["tinycloud.capabilities/read"]), "action-not-allowed"],
    ["another service's ability on a kv resource", kv(inside, ["tinycloud.vault/put"]), "action-not-allowed"],
    ["an sql ability on a kv resource", kv(inside, ["tinycloud.sql/write"]), "action-not-allowed"],
  ])("refuses %s", async (_label, entry, code) => {
    await refused(app([entry as PermissionEntry]), code);
  });

  it("accepts an ability written with its own service's namespace", async () => {
    await expect(signInWithManifest({ manifest: app([kv(inside, ["tinycloud.kv/get", "tinycloud.kv/put"])]), config: CONFIG })).resolves.toBeDefined();
  });

  // N3 / L4: prefixes match on exact path segments, and paths are compared literally, never normalised.
  it.each([
    ["v10/", "v1"], ["v10/", "v1/"], ["v1evil/x", "v1/"], ["v1-x", "v1"], ["v1/../v2/", "v2/x"], ["", "v1"],
    // A trailing-slash mismatch: an entry with a slash covers what is under it, not the bare name.
    ["v1", "v1/"],
  ])("a scope prefix does not accept a sibling that only starts the same: path %j under scope %j", async (path, prefix) => {
    const manifest = app([{ service: "tinycloud.kv", space: "applications", path: path === "" ? "/" : path, actions: ["get"], skipPrefix: true }]);
    await refused(manifest, "path-not-allowed", { allowedPathPrefixes: [prefix] });
  });

  it.each([["v1", "v1"], ["v1/", "v1"], ["v1/", "v1/"], ["v1/x/y", "v1"], ["v1/x/", "v1/"], ["v1/x", "v1/"]])("a scope prefix accepts the path and what is under it: path %j under scope %j", async (path, prefix) => {
    const manifest = app([{ service: "tinycloud.kv", space: "applications", path, actions: ["get"], skipPrefix: true }]);
    await expect(signInWithManifest({ manifest, config: CONFIG, allowedPathPrefixes: [prefix] })).resolves.toBeDefined();
  });

  // The node compares paths as literal strings. `a//b/x` is not under `a/b/` there, so it is refused here instead of being collapsed into a match.
  it.each([
    ["an empty segment in the middle", "a//b/x"], ["an empty segment before the prefix", "a//b/"], ["two trailing slashes", "a/b//"], ["a leading slash", "/a/b/x"],
    ["a dot segment", "a/./b/x"], ["a dot-dot segment", "a/b/../b/x"], ["a trailing dot-dot", "a/b/x/.."], ["a backslash", "a/b\\x"],
    ["a NUL", "a/b/x\u0000y"], ["a control character", "a/b/x\u001fy"], ["a delete character", "a/b/x\u007fy"],
    ["an encoded dot", "a/b/%2e%2e/x"], ["an encoded dot, upper case", "a/b/%2E/x"], ["an encoded slash", "a/b%2fx"], ["an encoded slash, upper case", "a/b/x%2Fy"],
    ["an encoded backslash", "a/b/x%5cy"], ["an encoded NUL", "a/b/x%00"],
  ])("refuses a path with %s even though it starts like the permitted one", async (_label, path) => {
    await refused(app([{ service: "tinycloud.kv", space: "applications", path, actions: ["get"], skipPrefix: true }]), "path-not-allowed", { allowedPathPrefixes: ["a/b/"] });
  });

  it("refuses the doubled slash the SDK makes of a prefix that ends in a slash with a path joined to it", async () => {
    // prefix "xyz.example.notes/" + path "data/" resolves to "xyz.example.notes//data/": what the node would hold is not what was meant.
    await refused(app([{ service: "tinycloud.kv", space: "applications", path: "data/", actions: ["get"] }]), "path-not-allowed");
    // Without the trailing slash on the prefix the join is one slash, and it is accepted.
    await expect(signInWithManifest({ manifest: app([{ service: "tinycloud.kv", space: "applications", path: "data/", actions: ["get"] }], { prefix: "xyz.example.notes" }), config: CONFIG })).resolves.toBeDefined();
  });

  it("still accepts the library's, Save's and an app's real paths, written the one way the node reads them", async () => {
    await expect(signInWithManifest({ manifest: shareManifest, ...SHARE_MANIFEST_SCOPE, config: CONFIG })).resolves.toBeDefined();
    await expect(signInWithManifest({ manifest: saveCopyManifest(), ...SAVE_COPY_MANIFEST_SCOPE, config: CONFIG })).resolves.toBeDefined();
    await expect(signInWithManifest({ manifest: app([kv("xyz.example.notes/app/", ["put"]), kv("xyz.example.notes/knowledge/", ["put"])]), config: CONFIG, allowedActions: ["put"], allowedPathPrefixes: ["xyz.example.notes/app/", "xyz.example.notes/knowledge/"] })).resolves.toBeDefined();
  });

  it("the manifest's own prefix, with or without its slash, never reaches a sibling", async () => {
    for (const prefix of ["xyz.example.notes", "xyz.example.notes/"]) {
      for (const path of ["xyz.example.notes-evil/", "xyz.example.notesevil/", "xyz.example.notes2/data/"]) {
        await refused(app([kv(path, ["get"])], { prefix }), "path-not-allowed");
      }
      await expect(signInWithManifest({ manifest: app([kv("xyz.example.notes/data/", ["get"])], { prefix }), config: CONFIG })).resolves.toBeDefined();
    }
  });

  // N4: what is checked is what is signed.
  it("a manifest changed while OpenKey is connecting is not what gets signed: the checked copy is, frozen", async () => {
    const original = app([kv(inside, ["get"])]);
    const grabbed = original.permissions!;
    state.onConnect = () => { grabbed.push(kv("/", ["get", "put", "del"], { space: "default" })); (original as { name: string }).name = "Changed"; };
    await signInWithManifest({ manifest: original, config: CONFIG });
    const signed = state.clients[0]!.config.manifest as Manifest;
    expect(signed).not.toBe(original);
    expect(signed.permissions).toHaveLength(1);
    expect(signed.name).toBe("Notes");
    // The copy cannot be changed after it was checked, deeply.
    expect(Object.isFrozen(signed)).toBe(true);
    expect(Object.isFrozen(signed.permissions)).toBe(true);
    expect(Object.isFrozen(signed.permissions![0])).toBe(true);
    expect(Object.isFrozen(signed.permissions![0]!.actions)).toBe(true);
    expect(() => { (signed.permissions as PermissionEntry[]).push(kv("/", ["get"])); }).toThrow();
  });

  it("a function manifest's result is copied and frozen too, and the original it handed out cannot change the grant", async () => {
    const handedOut: Manifest[] = [];
    const manifest = (): Manifest => { const made = app([kv(inside, ["get"])]); handedOut.push(made); return made; };
    state.onConnect = () => { for (const made of handedOut) made.permissions!.push(kv("/", ["get"], { space: "default" })); };
    await signInWithManifest({ manifest, config: CONFIG });
    const signed = state.clients[0]!.config.manifest as Manifest;
    expect(signed.permissions).toHaveLength(1);
    expect(Object.isFrozen(signed)).toBe(true);
  });

  // N6 / L2 / L3: names that reach the sign-in statement and OpenKey's window.
  const refusedName = async (appName: string): Promise<void> => {
    state.openKeys.length = 0;
    state.clients.length = 0;
    await expect(signInWithManifest({ manifest: saveCopyManifest(), ...SAVE_COPY_MANIFEST_SCOPE, config: CONFIG, appName }), JSON.stringify(appName)).rejects.toBeInstanceOf(SignInOptionError);
    expect(state.openKeys, "OpenKey must not open").toEqual([]);
    expect(state.clients).toEqual([]);
  };

  it.each([
    ["a newline and a forged field", "Evil\nURI: https://evil.example"],
    ["a carriage return", "Evil\rApp"], ["a tab", "Evil\tApp"], ["a NUL", "Evil\u0000App"], ["a delete", "Evil\u007fApp"],
    ["a right-to-left override", "Evil\u202eApp"], ["a bidi isolate", "Evil\u2066App"], ["a left-to-right mark", "Evil\u200eApp"], ["an Arabic letter mark", "Evil\u061cApp"],
    ["a line separator", "Evil\u2028App"], ["a paragraph separator", "Evil\u2029App"], ["a zero-width no-break space", "\ufeffEvil"],
    ["a zero-width space", "Evil\u200bApp"], ["a zero-width non-joiner", "Evil\u200cApp"], ["a zero-width joiner", "Evil\u200dApp"], ["a word joiner", "Evil\u2060App"],
    ["a soft hyphen", "Evil\u00adApp"], ["a Hangul filler", "Evil\u3164App"], ["a halfwidth Hangul filler", "Evil\uffa0App"], ["a Hangul choseong filler", "Evil\u115fApp"], ["a Hangul jungseong filler", "Evil\u1160App"],
    ["a Khmer inherent vowel", "Evil\u17b4App"], ["a Khmer inherent vowel aa", "Evil\u17b5App"], ["a Mongolian vowel separator", "Evil\u180eApp"], ["a combining grapheme joiner", "Evil\u034fApp"],
    ["a variation selector", "Evil\ufe0fApp"], ["a variation selector supplement", "Evil\u{e0100}App"], ["a tag character", "Evil\u{e0041}App"], ["the tag terminator", "Evil\u{e007f}App"],
    ["a private-use character", "Evil\ue000App"], ["an unassigned code point", "Evil\u0378App"], ["a lone surrogate", "Evil\ud800App"],
    ["a no-break space", "Evil\u00a0App"], ["an en space", "Evil\u2002App"], ["an ideographic space", "Evil\u3000App"], ["a narrow no-break space", "Evil\u202fApp"], ["a thin space", "Evil\u2009App"],
  ])("refuses an appName with %s", async (_label, name) => refusedName(name));

  it.each([
    ["more than 64 characters", "x".repeat(65)], ["more than 64 characters counted as characters, not bytes", "é".repeat(65)], ["nothing", ""], ["only spaces", "   "],
    ["a leading space", " Notes"], ["a trailing space", "Notes "], ["a double space", "Tiny  Notes"], ["text not in NFC form (e + combining acute)", "Cafe\u0301"],
  ])("refuses an appName with %s", async (_label, name) => refusedName(name));

  it.each([
    ["a bare host name", "evil.com"], ["a host name in a sentence", "Visit evil.com now"], ["a dotted host with a path", "a.b.c/x"], ["a host with a path", "evil.example/login"],
    ["a subdomain host", "login.evil.example"], ["a host with a hyphen", "my-evil.co"], ["a non-ASCII host", "bücher.de"],
    ["a URL", "Visit https://evil.example now"], ["a bare scheme URL", "ftp://x"], ["a www address", "go to www.evil.example"], ["an email address", "me@evil.example"], ["an at sign", "Notes @ home"],
    ["a division slash for the slashes", "https\u2215\u2215evil.example"], ["a fraction slash for the slashes", "https\u2044\u2044evil.example"], ["a full-width colon", "https\uff1a//evil.example"],
    ["a full-width solidus", "https:\uff0f\uff0fevil.example"], ["full-width dots", "evil\uff0ecom"], ["an ideographic full stop", "evil\u3002com"], ["a half-width ideographic full stop", "evil\uff61com"],
    ["a one-dot leader", "evil\u2024com"], ["a modifier-letter colon", "javascript\ua789alert(1)"],
    ["javascript:", "javascript:alert(1)"], ["javascript: with a space", "javascript: alert(1)"], ["mailto:", "mailto:a"], ["data:", "data:text/html,x"], ["tel:", "tel:+15555550100"], ["a scheme with no slashes", "http:evil"],
    ["vbscript:", "vbscript:x"], ["file:", "file:x"], ["blob:", "blob:x"], ["a scheme after a word", "Open javascript:x"],
    ["an IPv4 literal", "10.0.0.1"], ["an IPv4 in a sentence", "Notes at 192.168.1.1"], ["a bracketed IPv6 literal", "[::1]"], ["an IPv6 literal", "2001:db8::1"], ["a double colon", "Notes::Pro"],
    ["a backslash", "a\\b"], ["a UNC-like path", "\\\\evil\\share"],
  ])("refuses an appName with %s (a link or an address)", async (_label, name) => refusedName(name));

  it.each([
    "TinyCloud Share: install Tiny Notes", "TinyCloud Share", "Share (saved copies)", "Install v1.2", "Install v2.0.1", "Notes 📓", "Café ünïcode", "日本語のノート", "Tasks & Notes",
    "Install: v1", "Q3 report", "Notes - Work", "My App 2", "e.g. notes", "a".repeat(64), "é".repeat(64),
  ])("accepts the app name %j", async (appName) => {
    await signInWithManifest({ manifest: saveCopyManifest(), ...SAVE_COPY_MANIFEST_SCOPE, config: CONFIG, appName });
    expect(state.clients.at(-1)!.config.siweConfig).toEqual({ statement: `Sign in to ${appName}.` });
    expect(state.openKeys.at(-1)!.appName).toBe(appName);
  });

  it.each(["a/b", "a b", "../x", "x".repeat(65), "", "a\nb", "https://x", "a:b", "ünï", "a\u200bb", "a.b.com", " a", "a "])("refuses a sessionPrefix of %j", async (sessionPrefix) => {
    state.openKeys.length = 0;
    await expect(signInWithManifest({ manifest: saveCopyManifest(), ...SAVE_COPY_MANIFEST_SCOPE, config: CONFIG, sessionPrefix })).rejects.toBeInstanceOf(SignInOptionError);
    expect(state.openKeys).toEqual([]);
  });

  it.each(["tinycloud-share-install", "tinycloud_apps", "apps-1"])("accepts the sessionPrefix %j", async (sessionPrefix) => {
    await signInWithManifest({ manifest: saveCopyManifest(), ...SAVE_COPY_MANIFEST_SCOPE, config: CONFIG, sessionPrefix });
    expect(state.clients.at(-1)!.config.sessionStorageKeyPrefix).toBe(sessionPrefix);
  });

  it.each(["apps.tinycloud.xyz\u200b", "аpps.tinycloud.xyz", "apps.tinycloud.xyz\u3002", "a".repeat(254), "apps tinycloud.xyz"])("refuses a domain of %j: ASCII host names only", async (domain) => {
    state.openKeys.length = 0;
    await expect(signInWithManifest({ manifest: saveCopyManifest(), ...SAVE_COPY_MANIFEST_SCOPE, config: CONFIG, domain })).rejects.toBeInstanceOf(SignInOptionError);
    expect(state.openKeys).toEqual([]);
  });

  // L1: the connection this call opened is closed on ANY throw after OpenKey connects, and a connection the caller opened never is.
  describe("a connection the helper opened is closed on any throw after OpenKey connects", () => {
    const base = () => ({ manifest: saveCopyManifest(), ...SAVE_COPY_MANIFEST_SCOPE, config: CONFIG });
    const throwPoints: ReadonlyArray<readonly [string, () => Record<string, unknown>, () => void]> = [
      ["an onClient that throws", () => ({ onClient: () => { throw new Error("onClient failed"); } }), () => undefined],
      ["a shareOrigin that is not a URL", () => ({ config: { ...(CONFIG as object), shareOrigin: "not a url" } }), () => undefined],
      ["the SDK constructor throwing", () => ({}), () => { state.constructorError = new Error("constructor failed"); }],
      ["the sign-in throwing", () => ({}), () => { state.signInError = new Error("sign-in failed"); }],
      ["hosting a space throwing", () => ({ hostSpaces: ["files-for-you"] }), () => { state.hostError = new Error("host failed"); }],
      ["a function manifest that throws for the real account", () => ({ manifest: (address: string): Manifest => { if (address !== "0x0000000000000000000000000000000000000000") throw new Error("manifest failed"); return saveCopyManifest(); } }), () => undefined],
      ["a function manifest outside the scope for the real account", () => ({ manifest: (address: string): Manifest => address === "0x0000000000000000000000000000000000000000" ? saveCopyManifest() : app([kv("/", ["get"])]) }), () => undefined],
    ];

    it.each(throwPoints)("%s", async (_label, options, arrange) => {
      arrange();
      await expect(signInWithManifest({ ...base(), ...options() } as never)).rejects.toBeDefined();
      expect(state.openKeys).toHaveLength(1);
      expect(state.openKeys[0]!.disconnects, "the connection this call opened must be closed").toBeGreaterThanOrEqual(1);
    });

    it.each(throwPoints)("%s: a connection the caller opened is left open", async (_label, options, arrange) => {
      const session = await authenticateWithOpenKey(() => undefined);
      state.openKeys[0]!.disconnects = 0;
      arrange();
      await expect(signInWithManifest({ ...base(), ...options(), session } as never)).rejects.toBeDefined();
      expect(state.openKeys).toHaveLength(1);
      expect(state.openKeys[0]!.disconnects, "the caller's connection is not this call's to close").toBe(0);
    });

    it("an SDK client that was made is signed out when a later step throws", async () => {
      await expect(signInWithManifest({ ...base(), onClient: () => { throw new Error("onClient failed"); } })).rejects.toThrow("onClient failed");
      expect(state.clients[0]!.signedOut).toBe(1);
    });

    it("dispose closes a connection the helper opened, and leaves one the caller opened", async () => {
      const own = await signInWithManifest(base());
      await own.dispose();
      expect(state.openKeys[0]!.disconnects).toBe(1);
      const session = await authenticateWithOpenKey(() => undefined);
      const before = state.openKeys[1]!.disconnects;
      const given = await signInWithManifest({ ...base(), session });
      await given.dispose();
      expect(state.openKeys[1]!.disconnects).toBe(before);
      expect(state.clients[1]!.signedOut).toBe(1);
    });
  });

  // The SDK's own additions are the one documented exception; an SDK that adds more must fail here, not widen a session unseen.
  it("the permissions the SDK adds on top of a manifest are exactly the documented exception", () => {
    const withExtras = composeManifestRequest([saveCopyManifest()], { includeAccountRegistryPermissions: true }).resources;
    const without = composeManifestRequest([saveCopyManifest()], { includeAccountRegistryPermissions: false }).resources;
    const key = (entry: { service: string; space: string; path: string; actions: readonly string[] }): string => JSON.stringify([entry.service, entry.space, entry.path, [...entry.actions]]);
    const known = new Set(without.map(key));
    const added = withExtras.filter((entry) => !known.has(key(entry))).map(key).sort();
    expect(added).toEqual(SDK_ACCOUNT_REGISTRY_RESOURCES.map(key).sort());
    // And they are all in the one account space.
    expect(new Set(SDK_ACCOUNT_REGISTRY_RESOURCES.map((entry) => entry.space))).toEqual(new Set(["account"]));
  });

  it("the library's and Save's own manifests are inside their scopes", async () => {
    await expect(signInWithManifest({ manifest: shareManifest, ...SHARE_MANIFEST_SCOPE, config: CONFIG })).resolves.toBeDefined();
    await expect(signInWithManifest({ manifest: saveCopyManifest(), ...SAVE_COPY_MANIFEST_SCOPE, config: CONFIG })).resolves.toBeDefined();
    // The library's decrypt grant is for the signed-in account's own network, not anyone's.
    const foreign = shareManifest(SENDER.address);
    foreign.permissions = foreign.permissions!.map((entry) => entry.service === "tinycloud.encryption" ? { ...entry, path: ownerEncryptionNetwork(OTHER.address) } : entry);
    await expect(signInWithManifest({ manifest: () => foreign, ...SHARE_MANIFEST_SCOPE, config: CONFIG })).rejects.toMatchObject({ code: "path-not-allowed" });
  });

  it("only the explicitly named opt-in skips the check, and then the manifest goes through unchanged (as a frozen copy)", async () => {
    const delegation: PermissionEntry = { service: "tinycloud.delegation", space: "default", path: "/", actions: ["*"], skipPrefix: true };
    const broad = app([delegation], { defaults: true });
    const { tinycloud } = await signInWithManifest({ manifest: broad, config: CONFIG, unsafeAllowBroadManifest: true });
    expect(tinycloud).toBeDefined();
    expect(state.clients[state.clients.length - 1]!.config.manifest).toEqual(broad);
    // Anything but `true` is not the opt-in.
    await refused(app([delegation]), "delegation-ability", { unsafeAllowBroadManifest: false });
  });
});

describe("signInWithManifest options for an app-install flow", () => {
  beforeEach(() => {
    state.clients.length = 0;
    state.openKeys.length = 0;
    state.connectError = undefined;
    state.onConnect = undefined;
    state.constructorError = undefined;
    state.hostError = undefined;
    state.signInError = undefined;
    state.registrySync = undefined;
  });
  const manifest = () => saveCopyManifest();
  const base = { manifest, ...SAVE_COPY_MANIFEST_SCOPE, config: CONFIG };

  it("changes nothing for the callers that pass none of them", async () => {
    await signInWithManifest(base);
    const sdk = state.clients[0]!.config;
    expect(state.openKeys[0]!.appName).toBe("TinyCloud Share");
    expect(sdk.domain).toBe("share.tinycloud.xyz");
    expect(sdk.sessionStorageKeyPrefix).toBe("tinycloud-share");
    expect(sdk.sessionExpirationMs).toBe(MAX_SESSION_MS);
    expect(MAX_SESSION_MS).toBe(60 * 60 * 1000);
    expect(sdk.siweConfig).toEqual({ statement: "Sign in to TinyCloud Share." });
  });

  it("appName names the app in OpenKey and in the sign-in statement; domain and sessionPrefix replace the defaults", async () => {
    await signInWithManifest({ ...base, appName: "Tiny Notes", domain: "apps.tinycloud.xyz", sessionPrefix: "tinycloud-apps" });
    const sdk = state.clients[0]!.config;
    expect(state.openKeys[0]!.appName).toBe("Tiny Notes");
    expect(sdk.siweConfig).toEqual({ statement: "Sign in to Tiny Notes." });
    expect(sdk.domain).toBe("apps.tinycloud.xyz");
    expect(sdk.sessionStorageKeyPrefix).toBe("tinycloud-apps");
  });

  it("appName is for the OpenKey this call opens: a connection that already exists keeps its name", async () => {
    const session = await authenticateWithOpenKey(() => undefined);
    await signInWithManifest({ ...base, session, appName: "Tiny Notes" });
    expect(state.openKeys).toHaveLength(1);
    expect(state.openKeys[0]!.appName).toBe("TinyCloud Share");
  });

  it.each([["a URL", "https://apps.tinycloud.xyz"], ["a path", "apps.tinycloud.xyz/x"], ["a space", "apps tinycloud.xyz"], ["empty", ""], ["a user", "a@b.c"]])("refuses a domain that is %s, before OpenKey opens", async (_label, domain) => {
    await expect(signInWithManifest({ ...base, domain })).rejects.toBeInstanceOf(SignInOptionError);
    expect(state.openKeys).toEqual([]);
  });

  it("expiry shortens the session and can never lengthen it past one hour", async () => {
    await signInWithManifest({ ...base, expiry: 15 * 60 * 1000 });
    expect(state.clients[0]!.config.sessionExpirationMs).toBe(900_000);
    await signInWithManifest({ ...base, expiry: MAX_SESSION_MS });
    expect(state.clients[1]!.config.sessionExpirationMs).toBe(3_600_000);
    for (const expiry of [MAX_SESSION_MS + 1, 24 * 60 * 60 * 1000, 0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY]) {
      state.openKeys.length = 0;
      await expect(signInWithManifest({ ...base, expiry }), String(expiry)).rejects.toBeInstanceOf(SignInOptionError);
      expect(state.openKeys, `OpenKey must not open for expiry ${expiry}`).toEqual([]);
    }
  });

  it("waitForAccountRegistrySync waits for the SDK's pending sync, for at most its timeout, and never rejects", async () => {
    let finished = false;
    state.registrySync = { promise: new Promise((resolve) => setTimeout(() => { finished = true; resolve(undefined); }, 30)) };
    await signInWithManifest({ ...base, waitForAccountRegistrySync: true });
    expect(finished).toBe(true);

    state.registrySync = { promise: new Promise(() => undefined) };
    const started = Date.now();
    await signInWithManifest({ ...base, waitForAccountRegistrySync: { timeoutMs: 40 } });
    expect(Date.now() - started).toBeGreaterThanOrEqual(35);
    expect(Date.now() - started).toBeLessThan(2_000);

    state.registrySync = { promise: Promise.reject(new Error("registry down")) };
    await expect(signInWithManifest({ ...base, waitForAccountRegistrySync: true })).resolves.toBeDefined();
  });

  it("waitForAccountRegistrySync does not wait when it is off, absent or the SDK keeps no sync", async () => {
    state.registrySync = { promise: new Promise(() => undefined) };
    await signInWithManifest(base);
    await signInWithManifest({ ...base, waitForAccountRegistrySync: false });
    state.registrySync = undefined;
    await signInWithManifest({ ...base, waitForAccountRegistrySync: true });
    expect(state.clients).toHaveLength(3);
  });

  it("dispose closes the OpenKey flows and signs the in-memory session out, once, and never rejects", async () => {
    const signedIn = await signInWithManifest(base);
    const closedBefore = state.openKeys[0]!.disconnects;
    await signedIn.dispose();
    await signedIn.dispose();
    expect(state.clients[0]!.signedOut).toBe(1);
    expect(state.openKeys[0]!.disconnects).toBe(closedBefore + 1);
  });

  it("dispose does not reject when the SDK's sign-out does", async () => {
    const signedIn = await signInWithManifest(base);
    const record = state.clients[0]!;
    Object.defineProperty(record, "signedOut", { get: () => 0, set: () => { throw new Error("sign-out failed"); } });
    await expect(signedIn.dispose()).resolves.toBeUndefined();
  });

  it("a sign-in that fails disposes its session and rethrows the failure", async () => {
    state.signInError = new Error("signature refused");
    await expect(signInWithManifest(base)).rejects.toThrow("signature refused");
    expect(state.clients[0]!.signedOut).toBe(1);
    expect(state.openKeys[0]!.disconnects).toBeGreaterThanOrEqual(1);
  });
});


describe("ObservedOpenKeyProvider guards the wallet route too", () => {
  it("runs a personal_sign through the guard and other methods around it", async () => {
    const waits: string[] = [];
    const guard: ApprovalGuard = async (wait) => { waits.push("guarded"); return wait(); };
    const message = "hello";
    const hex = `0x${Buffer.from(message).toString("hex")}`;
    state.providerSignature = await SENDER.signMessage({ message });
    const provider = new ObservedOpenKeyProvider({} as never, {} as never, SENDER.address, undefined, guard);
    await expect(provider.request({ method: "personal_sign", params: [hex, SENDER.address] })).resolves.toBe(state.providerSignature);
    await provider.request({ method: "eth_chainId" });
    expect(waits).toEqual(["guarded"]);
  });
});
