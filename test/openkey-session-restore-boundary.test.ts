// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Manifest } from "@tinycloud/web-sdk";
import { signInWithManifest } from "../src/share/openkey-session.js";
import type { SharePublicConfig } from "../src/email-share/config.js";

let persisted = false;
const ADDRESS = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";

vi.mock("@tinycloud/web-sdk", () => ({
  TinyCloudWeb: class {
    constructor(readonly config: Record<string, unknown>) {}
    async restoreSession(): Promise<{ status: string }> {
      return { status: persisted ? "restored" : "missing" };
    }
    connectWallet(): void {}
    space(): { kv: object } { return { kv: {} }; }
    async signIn(): Promise<{ address: string; siwe: string }> {
      persisted = true;
      return { address: ADDRESS, siwe: "" };
    }
    async signOut(): Promise<void> { persisted = false; }
    async ensureOwnedSpaceHosted(name: string): Promise<string> { return name; }
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

function installOpenKeyFrameResponder(): { readonly count: () => number; readonly requests: unknown[] } {
  const requests: unknown[] = [];
  let count = 0;
  vi.spyOn(HTMLIFrameElement.prototype, "contentWindow", "get").mockReturnValue(window);
  vi.spyOn(window, "postMessage").mockImplementation((message) => {
    requests.push(message);
    if (typeof message !== "object" || message === null || !("type" in message) || message.type !== "openkey:auth:request") return;
    const request = message as { requestId?: unknown; protocolVersion?: unknown };
    queueMicrotask(() => {
      window.dispatchEvent(new MessageEvent("message", {
        origin: "https://openkey.so",
        source: window,
        data: { type: "openkey:auth:response", success: true, address: ADDRESS, keyId: "test-key", keyType: "MANAGED", requestId: request.requestId, protocolVersion: request.protocolVersion },
      }));
    });
  });
  const createElement = document.createElement.bind(document);
  vi.spyOn(document, "createElement").mockImplementation((tagName: string, options?: ElementCreationOptions) => {
    const element = createElement(tagName, options);
    if (tagName.toLowerCase() === "iframe") {
      count += 1;
      queueMicrotask(() => {
        window.dispatchEvent(new MessageEvent("message", { origin: "https://openkey.so", source: window, data: { type: "openkey:ready" } }));
      });
    }
    return element;
  });
  return { count: () => count, requests };
}

describe("persisted runner session OpenKey boundary", () => {
  beforeEach(() => {
    persisted = false;
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

    const reopened = await signInWithManifest(options);
    expect(transport.count()).toBe(1);
    expect(transport.requests).toHaveLength(1);
    await reopened.detach();
  });
});
