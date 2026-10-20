// @vitest-environment jsdom
import { beforeEach, describe, expect, it, vi } from "vitest";
import { privateKeyToAccount } from "viem/accounts";
import type { CallbackStrategy } from "@tinycloud/sdk-core";
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
import { ManifestRejectedError, type ManifestScope } from "../src/share/manifest-policy.js";
import { resetRevokeFlights, withWalletApproval } from "../src/share/revoke-flight.js";

const state = vi.hoisted(() => ({
  config: undefined as Record<string, unknown> | undefined,
  clients: [] as Array<{ config: Record<string, unknown>; hosted: string[]; order: string[]; signedOut: number }>,
  // OpenKey instances made, their app names, how many times each flow was closed, and whether connect fails.
  openKeys: [] as Array<{ appName: unknown; disconnects: number }>,
  connectError: undefined as unknown,
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
    async connect() { if (state.connectError !== undefined) throw state.connectError; return { address: state.sender, keyId: "key-1", keyType: "MANAGED" }; }
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
      state.config = config;
      this.record = { config, hosted: [], order: [], signedOut: 0 };
      state.clients.push(this.record);
    }
    async signIn(): Promise<void> { this.record.order.push("signIn"); if (state.signInError !== undefined) throw state.signInError; }
    async signOut(): Promise<void> { this.record.signedOut += 1; }
    async ensureOwnedSpaceHosted(name: string): Promise<string> { this.record.hosted.push(name); this.record.order.push(`host:${name}`); return name === "account" ? "account" : `space-of-${name}`; }
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
    expect(manifestOf(2)).toBe(APP_MANIFEST);
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

  it("makes every OpenKey wait go through the guard: connect, and each signature", async () => {
    const waits: string[] = [];
    const guardApproval: ApprovalGuard = async (wait) => { waits.push("wait"); return wait(); };
    await signInWithManifest({ manifest: saveCopyManifest(), ...SAVE_COPY_MANIFEST_SCOPE, config: CONFIG, guardApproval });
    expect(waits).toEqual(["wait"]);
    const strategy = state.config?.signStrategy as CallbackStrategy;
    await strategy.handler({ address: SENDER.address, chainId: 1, message: "siwe:sign-in", type: "siwe", purpose: "sign-in" });
    expect(waits).toEqual(["wait", "wait"]);
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
  });

  it("the library's and Save's own manifests are inside their scopes", async () => {
    await expect(signInWithManifest({ manifest: shareManifest, ...SHARE_MANIFEST_SCOPE, config: CONFIG })).resolves.toBeDefined();
    await expect(signInWithManifest({ manifest: saveCopyManifest(), ...SAVE_COPY_MANIFEST_SCOPE, config: CONFIG })).resolves.toBeDefined();
    // The library's decrypt grant is for the signed-in account's own network, not anyone's.
    const foreign = shareManifest(SENDER.address);
    foreign.permissions = foreign.permissions!.map((entry) => entry.service === "tinycloud.encryption" ? { ...entry, path: ownerEncryptionNetwork(OTHER.address) } : entry);
    await expect(signInWithManifest({ manifest: () => foreign, ...SHARE_MANIFEST_SCOPE, config: CONFIG })).rejects.toMatchObject({ code: "path-not-allowed" });
  });

  it("only the explicitly named opt-in skips the check, and then the manifest goes through unchanged", async () => {
    const delegation: PermissionEntry = { service: "tinycloud.delegation", space: "default", path: "/", actions: ["*"], skipPrefix: true };
    const broad = app([delegation], { defaults: true });
    const { tinycloud } = await signInWithManifest({ manifest: broad, config: CONFIG, unsafeAllowBroadManifest: true });
    expect(tinycloud).toBeDefined();
    expect(state.clients[state.clients.length - 1]!.config.manifest).toBe(broad);
    // Anything but `true` is not the opt-in.
    await refused(app([delegation]), "delegation-ability", { unsafeAllowBroadManifest: false });
  });
});

describe("signInWithManifest options for an app-install flow", () => {
  beforeEach(() => {
    state.clients.length = 0;
    state.openKeys.length = 0;
    state.connectError = undefined;
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
