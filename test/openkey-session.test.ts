// @vitest-environment jsdom
import { beforeEach, describe, expect, it, vi } from "vitest";
import { privateKeyToAccount } from "viem/accounts";
import type { CallbackStrategy } from "@tinycloud/sdk-core";
import type { Manifest } from "@tinycloud/web-sdk";
import {
  authenticateWithOpenKey,
  createTinyCloudClient,
  filesForYouPermissions,
  ObservedOpenKeyProvider,
  ownerEncryptionNetwork,
  saveCopyManifest,
  shareManifest,
  signInWithManifest,
  type ApprovalGuard,
} from "../src/share/openkey-session.js";
const state = vi.hoisted(() => ({
  config: undefined as Record<string, unknown> | undefined,
  clients: [] as Array<{ config: Record<string, unknown>; hosted: string[]; order: string[] }>,
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
    async connect() { return { address: state.sender, keyId: "key-1", keyType: "MANAGED" }; }
    getSessionToken() { return null; }
    tinycloudSigningOptions() { return { endpoint: "https://api.openkey.so/api/delegate/sign", token: null }; }
    async signMessage(request: { message: string; keyId?: string }) {
      state.signed.push(request);
      const signature = state.omitSignature ? undefined : await state.signer!.signMessage({ message: request.message });
      return { address: state.sender, signature };
    }
  },
  OpenKeyProvider: class { async request(): Promise<string> { return state.providerSignature; } },
}));

vi.mock("@tinycloud/web-sdk", () => ({
  TinyCloudWeb: class {
    private readonly record: { config: Record<string, unknown>; hosted: string[]; order: string[] };
    constructor(config: Record<string, unknown>) {
      state.config = config;
      this.record = { config, hosted: [], order: [] };
      state.clients.push(this.record);
    }
    async signIn(): Promise<void> { this.record.order.push("signIn"); }
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

describe("signInWithManifest: one sign-in, any manifest", () => {
  beforeEach(() => {
    state.config = undefined;
    state.clients.length = 0;
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
    permissions: [{ service: "tinycloud.kv", space: "applications", path: "xyz.example.notes/data/", actions: ["get", "put"], skipPrefix: true }],
  };

  it("signs in with the manifest it is given: Share's library manifest and the viewer's save manifest are different sessions", async () => {
    const library = await signInWithManifest({ manifest: shareManifest, config: CONFIG });
    const save = await signInWithManifest({ manifest: saveCopyManifest(), config: CONFIG });
    const app = await signInWithManifest({ manifest: APP_MANIFEST, config: CONFIG });

    const manifests = state.clients.map((client) => client.config.manifest as Manifest);
    expect(manifests).toHaveLength(3);
    expect(manifests[0]!.permissions).toContainEqual(expect.objectContaining({ service: "tinycloud.encryption" }));
    expect(manifests[0]!.permissions).toEqual(shareManifest(SENDER.address).permissions);
    // The viewer's manifest asks for the private copies area and nothing else.
    expect(manifests[1]!.permissions).toEqual(filesForYouPermissions());
    expect(manifests[1]!.permissions!.map((entry) => entry.service)).toEqual(["tinycloud.kv"]);
    expect(manifests[2]).toBe(APP_MANIFEST);
    // Each caller gets a session of its own, tied to the address OpenKey connected.
    expect(new Set([library.tinycloud, save.tinycloud, app.tinycloud]).size).toBe(3);
    for (const signedIn of [library, save, app]) expect(signedIn.session.address).toBe(SENDER.address);
  });

  it("gives a manifest function the connected address", async () => {
    const seen: string[] = [];
    await signInWithManifest({ manifest: (address) => { seen.push(address); return APP_MANIFEST; }, config: CONFIG });
    expect(seen).toEqual([SENDER.address]);
    expect(shareManifest(SENDER.address).permissions).toContainEqual(expect.objectContaining({ path: ownerEncryptionNetwork(SENDER.address) }));
  });

  it("hosts the account space first, then each named space once, and returns the ids", async () => {
    const { spaces } = await signInWithManifest({ manifest: saveCopyManifest(), config: CONFIG, hostSpaces: ["files-for-you", "account", "files-for-you"] });
    expect(state.clients[0]!.order).toEqual(["signIn", "host:account", "host:files-for-you"]);
    expect(spaces).toEqual({ account: "account", "files-for-you": "space-of-files-for-you" });
  });

  it("keeps the session in memory: nothing is persisted, and no storage is written", async () => {
    await signInWithManifest({ manifest: saveCopyManifest(), config: CONFIG, hostSpaces: ["files-for-you"] });
    expect(state.clients[0]!.config.persistSession).toBe(false);
    expect(localStorage.length).toBe(0);
    expect(sessionStorage.length).toBe(0);
  });

  it("reuses an OpenKey connection that already exists instead of opening OpenKey again", async () => {
    const session = await authenticateWithOpenKey(() => undefined);
    const { session: used } = await signInWithManifest({ manifest: saveCopyManifest(), config: CONFIG, session });
    expect(used).toBe(session);
  });

  it("makes every OpenKey wait go through the guard: connect, and each signature", async () => {
    const waits: string[] = [];
    const guardApproval: ApprovalGuard = async (wait) => { waits.push("wait"); return wait(); };
    await signInWithManifest({ manifest: saveCopyManifest(), config: CONFIG, guardApproval });
    // Connect is the first wait.
    expect(waits).toEqual(["wait"]);
    const strategy = state.config?.signStrategy as CallbackStrategy;
    await strategy.handler({ address: SENDER.address, chainId: 1, message: "siwe:sign-in", type: "siwe", purpose: "sign-in" });
    expect(waits).toEqual(["wait", "wait"]);
  });

  it("hands the client out before sign-in so a failed approval can still be read", async () => {
    let stepsWhenHandedOut: string[] | undefined;
    await signInWithManifest({ manifest: saveCopyManifest(), config: CONFIG, onClient: () => { stepsWhenHandedOut = [...state.clients[0]!.order]; } });
    expect(stepsWhenHandedOut).toEqual([]);
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
