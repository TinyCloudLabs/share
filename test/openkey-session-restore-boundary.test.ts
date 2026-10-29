// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { privateKeyToAccount } from "viem/accounts";
import type { Manifest } from "@tinycloud/web-sdk";
import { signInWithManifest } from "../src/share/openkey-session.js";
import type { SharePublicConfig } from "../src/email-share/config.js";
import { catalog } from "../src/apps/catalog.ts";
import { installRecordPlan } from "../src/apps/run.ts";
import { createRunPorts } from "../src/apps/run-session.ts";

vi.mock("../src/email-share/config.js", () => ({
  loadSharePublicConfig: async () => ({
    version: "tinycloud.share/config-v2",
    shareOrigin: "https://share.tinycloud.xyz",
    senderBootstrapNodeOrigin: "https://node.tinycloud.xyz",
    registryOrigin: "https://registry.tinycloud.xyz",
    credentialsOrigin: "https://credentials.tinycloud.xyz",
    accountlessReceiverEnabled: false,
  }),
}));

let persisted = false;
let covered = true;
let walletAttached = false;
const SIGNER = privateKeyToAccount("0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d");
let signFreshManifest = false;
let applicationSpaceExists = true;
const permissionRequests: unknown[] = [];
const hostedSpaces: string[] = [];
const clientConfigs: Array<Record<string, unknown>> = [];
const ADDRESS = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";

vi.mock("@tinycloud/web-sdk", () => ({
  TinyCloudWeb: class {
    constructor(readonly config: Record<string, unknown>) { clientConfigs.push(config); }
    async restoreSession(): Promise<{ status: string }> {
      return { status: persisted ? "restored" : "missing" };
    }
    connectWallet(): void { walletAttached = true; }
    hasPermissions(): boolean { return covered; }
    space(name: string): { id: string; kv: object } {
      return { id: name, kv: { list: async () => ({ ok: true, data: { keys: [] } }), createSignedReadUrl: async () => ({ ok: false, error: { code: "KV_NOT_FOUND" } }) } };
    }
    sqlForSpace(): object { return {}; }
    private async approve(message: string, purpose: string): Promise<void> {
      const strategy = this.config["signStrategy"] as { handler: (request: { message: string; purpose: string }) => Promise<unknown> };
      await strategy.handler({ message, purpose });
    }
    async signIn(): Promise<{ address: string; siwe: string }> {
      if (!persisted && signFreshManifest) await this.approve("Health Log manifest", "sign-in");
      if (!applicationSpaceExists && this.config["autoCreateSpace"] === true) {
        await this.approve("Create applications space", "space-host");
        applicationSpaceExists = true;
      }
      persisted = true;
      return { address: ADDRESS, siwe: "" };
    }
    async requestPermissions(permissions: unknown[]): Promise<{ approved: boolean }> {
      permissionRequests.push(permissions);
      await this.approve("Health Log settings permission", "runtime-permission");
      return { approved: true };
    }
    async signOut(): Promise<void> { persisted = false; }
    async ensureOwnedSpaceHosted(name: string): Promise<string> {
      if (!walletAttached) throw new Error("Not signed in. Call signIn() first.");
      hostedSpaces.push(name);
      return name;
    }
  },
}));

const CONFIG: SharePublicConfig = {
  version: "tinycloud.share/config-v2",
  shareOrigin: "https://share.tinycloud.xyz",
  senderBootstrapNodeOrigin: "https://node.tinycloud.xyz",
  registryOrigin: "https://registry.tinycloud.xyz",
  credentialsOrigin: "https://credentials.tinycloud.xyz",
  accountlessReceiverEnabled: false,
};
const MANIFEST: Manifest = {
  manifest_version: 1,
  app_id: "xyz.example.restore-boundary",
  name: "Restore boundary",
  space: "applications",
  defaults: false,
  includePublicSpace: false,
  permissions: [],
};

function installOpenKeyFrameResponder(): {
  readonly count: () => number;
  readonly requests: unknown[];
  readonly authRequests: () => number;
  readonly signRequests: () => number;
} {
  const requests: unknown[] = [];
  let count = 0;
  const messageType = (message: unknown): unknown => typeof message === "object" && message !== null && "type" in message ? message.type : undefined;
  vi.spyOn(HTMLIFrameElement.prototype, "contentWindow", "get").mockReturnValue(window);
  vi.spyOn(window, "postMessage").mockImplementation((message) => {
    requests.push(message);
    if (typeof message !== "object" || message === null || !("type" in message)) return;
    if (message.type === "openkey:auth:request") {
      const request = message as { requestId?: unknown; protocolVersion?: unknown };
      queueMicrotask(() => window.dispatchEvent(new MessageEvent("message", {
        origin: "https://openkey.so",
        source: window,
        data: { type: "openkey:auth:response", success: true, address: ADDRESS, keyId: "test-key", keyType: "MANAGED", requestId: request.requestId, protocolVersion: request.protocolVersion },
      })));
    } else if (message.type === "openkey:sign:request") {
      const request = message as { message: string };
      void SIGNER.signMessage({ message: request.message }).then((signature) => {
        window.dispatchEvent(new MessageEvent("message", {
          origin: "https://openkey.so",
          source: window,
          data: { type: "openkey:sign:response", success: true, signature, address: ADDRESS },
        }));
      });
    }
  });
  const createElement = document.createElement.bind(document);
  vi.spyOn(document, "createElement").mockImplementation((tagName: string, options?: ElementCreationOptions) => {
    const element = createElement(tagName, options);
    if (tagName.toLowerCase() === "iframe") {
      count += 1;
      queueMicrotask(() => window.dispatchEvent(new MessageEvent("message", { origin: "https://openkey.so", source: window, data: { type: "openkey:ready" } })));
    }
    return element;
  });
  return {
    count: () => count,
    requests,
    authRequests: () => requests.filter((request) => messageType(request) === "openkey:auth:request").length,
    signRequests: () => requests.filter((request) => messageType(request) === "openkey:sign:request").length,
  };
}

describe("persisted runner session OpenKey boundary", () => {
  beforeEach(() => {
    persisted = false;
    covered = true;
    walletAttached = false;
    signFreshManifest = false;
    applicationSpaceExists = true;
    permissionRequests.length = 0;
    hostedSpaces.length = 0;
    clientConfigs.length = 0;
    document.body.replaceChildren();
    vi.stubGlobal("matchMedia", () => ({ matches: false, addListener: () => undefined, removeListener: () => undefined, addEventListener: () => undefined, removeEventListener: () => undefined }));
  });

  afterEach(() => {
    document.body.replaceChildren();
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it("opens one real OpenKey auth iframe on a fresh session and none on a covered reopen", async () => {
    const transport = installOpenKeyFrameResponder();
    const options = {
      manifest: MANIFEST,
      config: CONFIG,
      persistSession: true,
      restoreBeforeOpenKey: true,
      includeAccountRegistryPermissions: false,
      autoCreateSpace: false,
    };

    const first = await signInWithManifest(options);
    expect(transport.count()).toBe(1);
    expect(transport.requests).toHaveLength(1);
    expect(transport.requests[0]).toMatchObject({ type: "openkey:auth:request" });
    await first.detach();
    const coveredPermission = [{ service: "tinycloud.kv", space: "applications", path: "xyz.example.restore-boundary/settings/", actions: ["put"] }];
    await first.preparePermissionRequest(coveredPermission);
    expect(transport.count()).toBe(1);

    const reopened = await signInWithManifest(options);
    expect(transport.count()).toBe(1);
    expect(transport.requests).toHaveLength(1);
    await reopened.preparePermissionRequest(coveredPermission);
    expect(transport.count()).toBe(1);
    await reopened.detach();
  });
  it("a fresh app consent uses one real OpenKey signature and a covered reopen uses none", async () => {
    signFreshManifest = true;
    const transport = installOpenKeyFrameResponder();
    const options = {
      manifest: MANIFEST,
      config: CONFIG,
      persistSession: true,
      restoreBeforeOpenKey: true,
      includeAccountRegistryPermissions: false,
      autoCreateSpace: true,
    };

    const first = await signInWithManifest(options);
    expect(SIGNER.address).toBe(ADDRESS);
    expect(clientConfigs[0]).toMatchObject({ autoCreateSpace: true, includeAccountRegistryPermissions: false });
    expect(transport.authRequests()).toBe(1);
    expect(transport.signRequests()).toBe(1);
    expect(hostedSpaces).toEqual([]);
    await first.detach();

    walletAttached = false;
    const reopened = await signInWithManifest(options);
    expect(transport.authRequests()).toBe(1);
    expect(transport.signRequests()).toBe(1);
    expect(hostedSpaces).toEqual([]);
    expect(persisted).toBe(true);
    await reopened.detach();
  });
  it("the real runner restores its app session before any space-host call", async () => {
    signFreshManifest = true;
    const transport = installOpenKeyFrameResponder();
    const entry = catalog.apps.find((candidate) => candidate.app_id === "xyz.tinycloud.sample.healthlog");
    if (entry === undefined) throw new Error("Health Log catalog entry is missing");
    const ports = createRunPorts();
    const plan = installRecordPlan(entry);
    const hooks = { approval: () => undefined };

    const first = await ports.signIn(entry, plan, hooks);
    expect(transport.authRequests()).toBe(1);
    expect(transport.signRequests()).toBe(1);
    await first.runtime.detach();

    walletAttached = false;
    hostedSpaces.length = 0;
    const reopened = await ports.signIn(entry, plan, hooks);
    expect(transport.authRequests()).toBe(1);
    expect(transport.signRequests()).toBe(1);
    expect(hostedSpaces).toEqual([]);
    expect(persisted).toBe(true);
    await reopened.runtime.detach();
  });

  it("a fresh account with no applications space needs the production space-creation approval once", async () => {
    signFreshManifest = true;
    applicationSpaceExists = false;
    const transport = installOpenKeyFrameResponder();
    const options = {
      manifest: MANIFEST,
      config: CONFIG,
      persistSession: true,
      restoreBeforeOpenKey: true,
      includeAccountRegistryPermissions: false,
      autoCreateSpace: true,
    };

    const first = await signInWithManifest(options);
    expect(applicationSpaceExists).toBe(true);
    expect(transport.authRequests()).toBe(1);
    expect(transport.signRequests()).toBe(2);
    await first.detach();

    walletAttached = false;
    const reopened = await signInWithManifest(options);
    expect(transport.authRequests()).toBe(1);
    expect(transport.signRequests()).toBe(2);
    expect(persisted).toBe(true);
    await reopened.detach();
  });

  it("a version step-up signs only its uncovered setting permission once", async () => {
    persisted = true;
    covered = false;
    const transport = installOpenKeyFrameResponder();
    const signedIn = await signInWithManifest({
      manifest: MANIFEST,
      config: CONFIG,
      persistSession: true,
      restoreBeforeOpenKey: true,
      includeAccountRegistryPermissions: false,
      autoCreateSpace: false,
    });
    const added = [{ service: "tinycloud.kv", space: "applications", path: "xyz.example.restore-boundary/settings/", actions: ["get", "put"], skipPrefix: true }];

    expect(transport.authRequests()).toBe(0);
    expect(transport.signRequests()).toBe(0);
    await signedIn.preparePermissionRequest(added);
    const result = await signedIn.tinycloud.requestPermissions(added);
    expect(result.approved).toBe(true);
    expect(permissionRequests).toEqual([added]);
    expect(transport.authRequests()).toBe(1);
    expect(transport.signRequests()).toBe(1);
    await signedIn.detach();
  });

  it("attaches OpenKey to the restored client before an uncovered grant", async () => {
    persisted = true;
    covered = false;
    const transport = installOpenKeyFrameResponder();
    const signedIn = await signInWithManifest({
      manifest: MANIFEST,
      config: CONFIG,
      persistSession: true,
      restoreBeforeOpenKey: true,
      includeAccountRegistryPermissions: false,
      autoCreateSpace: false,
    });

    expect(transport.count()).toBe(0);
    await signedIn.preparePermissionRequest([
      { service: "tinycloud.kv", space: "applications", path: "xyz.example.restore-boundary/settings/", actions: ["put"], skipPrefix: true },
    ]);
    expect(transport.requests).toHaveLength(1);
    expect(transport.requests[0]).toMatchObject({ type: "openkey:auth:request" });
    expect(walletAttached).toBe(true);
    await signedIn.detach();
  });
});
