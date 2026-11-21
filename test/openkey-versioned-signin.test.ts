// @vitest-environment jsdom
import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  authenticateWithOpenKey,
  createTinyCloudClient,
  SHARE_MANIFEST_SCOPE,
  shareManifest,
  signInWithManifest,
  takeWalletApprovalFailure,
  type ApprovalInfo,
  type ShareTinyCloud,
} from "../src/share/openkey-session.js";
import { authFailureMessage, SENDER_FAILURE } from "../src/share/sender-failure.js";

const ADDRESS = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";
const OTHER_ADDRESS = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC";

const recapSiwe = (att: Record<string, Record<string, unknown[]>>): string =>
  `app.example wants you to sign in with your Ethereum account:\n${ADDRESS}\n\nSign in.\n\nResources:\n- urn:recap:${Buffer.from(JSON.stringify({ att })).toString("base64url")}`;

const ASKED = recapSiwe({
  "tinycloud:space-a/kv/one": { "tinycloud.kv/get": [], "tinycloud.kv/put": [] },
  "tinycloud:space-a/kv/two": { "tinycloud.kv/get": [] },
});
const NARROWED = recapSiwe({
  "tinycloud:space-a/kv/one": { "tinycloud.kv/get": [] },
  "tinycloud:space-a/kv/two": { "tinycloud.kv/get": [] },
});

const state = vi.hoisted(() => ({
  clients: [] as Array<{ config: Record<string, unknown> }>,
  authorized: [] as Array<{ request: Record<string, unknown>; opts: unknown }>,
  signMessages: 0,
  signedOut: 0,
  answer: undefined as undefined | ((request: { siwe: string }) => Promise<unknown>),
  signInOutcome: [] as Array<"authorized" | "legacy">,
}));

vi.mock("@openkey/sdk", () => ({
  OpenKey: class {
    disconnect() {}
    async connect() { return { address: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8", keyId: "key-1", keyType: "MANAGED" }; }
    async signMessage() { state.signMessages += 1; return { address: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8", signature: "0x00" }; }
    async authorizeTinyCloud(request: { siwe: string }, opts: unknown) {
      state.authorized.push({ request: request as never, opts });
      return state.answer!(request);
    }
  },
  OpenKeyProvider: class { async request(): Promise<string> { return "0x00"; } },
}));

// The Web SDK's sign-in with `config.openkey`: it calls the client's `authorizeTinyCloud` and builds the session from the answer.
vi.mock("@tinycloud/web-sdk", () => ({
  TinyCloudWeb: class {
    readonly config: Record<string, unknown>;
    constructor(config: Record<string, unknown>) { this.config = config; state.clients.push({ config }); }
    get sessionRestoreStatus() { return "idle"; }
    get spaceId() { return "applications-space"; }
    readonly account = { spaces: { get: async () => ({ ok: true, data: {} }) } };
    async signIn(): Promise<{ address: string; siwe: string }> {
      const openkey = this.config.openkey as undefined | { client: { authorizeTinyCloud(request: unknown, opts: unknown): Promise<{ signedMessage: string }> }; mode: string };
      if (openkey === undefined) { state.signInOutcome.push("legacy"); return { address: ADDRESS, siwe: "siwe" }; }
      const result = await openkey.client.authorizeTinyCloud({ protocolVersion: 1, siwe: ASKED, jwk: {} }, { mode: openkey.mode });
      state.signInOutcome.push("authorized");
      return { address: ADDRESS, siwe: result.signedMessage };
    }
    async signOut(): Promise<void> { state.signedOut += 1; }
    async ensureOwnedSpaceHosted(name: string): Promise<string> { return name; }
  },
}));

const CONFIG = {
  shareOrigin: "https://share.tinycloud.xyz",
  senderBootstrapNodeOrigin: "https://tee.node.tinycloud.xyz",
  registryOrigin: "https://registry.tinycloud.xyz",
} as never;

const approve = (signedMessage: string, address = ADDRESS) => async () => ({
  protocolVersion: 1, address, signature: "0x00", signedMessage, selectedActionKeys: [], permissions: [],
});

beforeEach(() => {
  state.clients.length = 0;
  state.authorized.length = 0;
  state.signMessages = 0;
  state.signedOut = 0;
  state.signInOutcome.length = 0;
  state.answer = approve(ASKED);
  localStorage.clear();
});

describe("the library sign-in reaches OpenKey through the versioned authorizeTinyCloud", () => {
  it("signs the library in with config.openkey, and no byte-exact signature", async () => {
    const session = await authenticateWithOpenKey(() => undefined);
    await createTinyCloudClient(session, CONFIG, () => undefined);

    expect(state.signInOutcome).toEqual(["authorized"]);
    expect(state.authorized).toHaveLength(1);
    expect(state.authorized[0]!.opts).toEqual({ mode: "iframe" });
    // The signed-in key is named, as the byte-exact path names it.
    expect(state.authorized[0]!.request).toMatchObject({ protocolVersion: 1, keyId: "key-1" });
    expect(state.signMessages).toBe(0);
  });

  it("leaves every other sign-in on the byte-exact path", async () => {
    await signInWithManifest({ manifest: shareManifest, ...SHARE_MANIFEST_SCOPE, config: CONFIG });

    expect(state.clients[0]!.config.openkey).toBeUndefined();
    expect(state.signInOutcome).toEqual(["legacy"]);
    expect(state.authorized).toHaveLength(0);
  });

  it("counts the approval through the caller's guard as one signature", async () => {
    const seen: Array<ApprovalInfo | undefined> = [];
    await signInWithManifest({
      manifest: shareManifest, ...SHARE_MANIFEST_SCOPE, config: CONFIG, versionedSignIn: true,
      guardApproval: (wait, info) => { seen.push(info); return wait(); },
    });

    expect(seen).toContainEqual({ kind: "connect" });
    expect(seen.filter((info) => info?.kind === "sign")).toEqual([{ kind: "sign" }]);
  });
});

describe("a versioned approval that does not give the library a usable session", () => {
  async function failedSignIn(): Promise<{ error: unknown; client: ShareTinyCloud }> {
    let client: ShareTinyCloud | undefined;
    const error = await signInWithManifest({
      manifest: shareManifest, ...SHARE_MANIFEST_SCOPE, config: CONFIG, versionedSignIn: true, onClient: (made) => { client = made; },
    }).then(() => undefined, (caught: unknown) => caught);
    return { error, client: client! };
  }

  it("surfaces a closed OpenKey window as a cancelled approval", async () => {
    state.answer = async () => { throw { code: "USER_CANCELLED" }; };
    const { error, client } = await failedSignIn();

    expect(error).toEqual({ code: "USER_CANCELLED" });
    expect(takeWalletApprovalFailure(client)).toBe("cancelled");
    expect(takeWalletApprovalFailure(client)).toBeUndefined();
  });

  it("surfaces an unanswered OpenKey window as a timeout", async () => {
    state.answer = async () => { throw { code: "TIMEOUT" }; };
    const { client } = await failedSignIn();

    expect(takeWalletApprovalFailure(client)).toBe("timeout");
  });

  it("refuses a result signed for another account", async () => {
    state.answer = approve(ASKED, OTHER_ADDRESS);
    const { error, client } = await failedSignIn();

    expect(error).toEqual(new Error("wallet-approval-wrong-account"));
    expect(takeWalletApprovalFailure(client)).toBe("wrong-account");
  });

  it("refuses an approval from which the person removed a grant the library asked for, saying what to do, and leaves no session", async () => {
    state.answer = approve(NARROWED);
    const { error } = await failedSignIn();

    expect(authFailureMessage(error)).toMatch(/needs all the permissions it asks for.*allow each one/);
    expect(authFailureMessage(error)).not.toBe(SENDER_FAILURE.signIn);
    // The half-made client is signed out, so nothing is saved or kept for a later restore.
    expect(state.signedOut).toBe(1);
  });

  it("accepts an approval that keeps every grant", async () => {
    await expect(signInWithManifest({ manifest: shareManifest, ...SHARE_MANIFEST_SCOPE, config: CONFIG, versionedSignIn: true })).resolves.toBeDefined();
  });
});
