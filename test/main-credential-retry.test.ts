// @vitest-environment jsdom
import { beforeEach, describe, expect, it, vi } from "vitest";

const state = vi.hoisted(() => ({
  authenticate: vi.fn(),
  createAccountClient: vi.fn(),
  receive: vi.fn(),
  receiveWithSdk: vi.fn(),
  get: vi.fn(),
  importInto: vi.fn(),
  resolve: vi.fn(),
  presented: [] as { result: unknown; options: Record<string, unknown> }[],
  resolved: undefined as unknown,
  invalid: vi.fn(),
  events: [] as string[],
}));

vi.mock("../src/email-share/url.js", () => ({
  captureAndScrubLaunch: () => {
    state.events.push("scrub");
    return { shareHref: "https://share.tinycloud.xyz/s/inline#v=2&p=test", kind: "addressed" };
  },
}));

vi.mock("../src/email-share/view.js", () => ({
  renderRecipientInvalid: (...args: unknown[]) => state.invalid(...args),
  renderRecipientLoading: () => undefined,
}));

vi.mock("../src/email-share/config.js", () => ({
  loadSharePublicConfig: async () => ({
    version: "tinycloud.share/config-v2",
    shareOrigin: "https://share.tinycloud.xyz",
    senderBootstrapNodeOrigin: "https://tee.node.tinycloud.xyz",
    registryOrigin: "https://registry.tinycloud.xyz",
    credentialsOrigin: "https://credentials.example",
    accountlessReceiverEnabled: true,
  }),
}));

vi.mock("../src/viewer/resolve.js", () => ({
  createBrowserAddressedAuthorization: () => undefined,
  presentationEnvelope: (metadata: unknown, content: { readonly filename: string; readonly mediaType: string }) => ({ version: 1, display: { filename: content.filename }, metadata: { filename: content.filename, mediaType: content.mediaType }, target: { resource: { path: content.filename } }, expiry: (metadata as { expiresAt: string }).expiresAt }),
  resolveShare: (...args: unknown[]) => state.resolve(...args),
}));

vi.mock("../src/viewer/present.js", () => ({
  presentShare: async (_root: HTMLElement, result: unknown, options: Record<string, unknown>) => {
    state.presented.push({ result, options });
  },
}));

vi.mock("../src/share/receiver.js", () => ({
  createShareReceiverClient: () => ({ share: { receive: (...args: unknown[]) => state.receive(...args) } }),
}));

vi.mock("../src/viewer/sdk-accountless-receiver.js", () => ({
  receiveWithSdk: (...args: unknown[]) => state.receiveWithSdk(...args),
}));

vi.mock("@tinycloud/web-sdk-wasm", () => ({ tinycloud: { invoke: vi.fn() } }));

vi.mock("@tinycloud/share-sdk", () => ({ createRegisteredPolicyAuthority: () => ({}) }));

vi.mock("../src/share/openkey-session.js", () => ({
  authenticateWithOpenKey: (...args: unknown[]) => state.authenticate(...args),
  createTinyCloudClient: (...args: unknown[]) => state.createAccountClient(...args),
}));

beforeEach(() => {
  vi.resetModules();
  document.body.innerHTML = '<div id="viewer"></div>';
  window.history.replaceState(null, "", "/viewer.html#secret");
  state.authenticate.mockReset();
  state.createAccountClient.mockReset();
  state.receive.mockReset();
  state.receiveWithSdk.mockReset();
  state.get.mockReset();
  state.importInto.mockReset();
  state.resolve.mockReset();
  state.invalid.mockReset();
  state.events.length = 0;
  state.presented.length = 0;
  const envelope = {
    version: 3,
    recipientMatcher: { kind: "exactEmail", value: "reader@example.com" },
    display: { filename: "report.md" },
    metadata: { filename: "report.md", mediaType: "text/plain" },
    policyEngine: {
      endpoint: "https://policy.example",
      audience: "tinycloud://policy-engine",
      grantIssuerDid: "did:key:z6MkGrantIssuer",
      policyId: "urn:tinycloud:policy:test",
      requirementId: "urn:tinycloud:requirement:test",
    },
  };
  state.resolved = {
    state: "policy-authorization-required",
    envelope,
    shareCid: "bafkreicredentialshare",
  };
  state.resolve.mockImplementation(async () => {
    return state.resolved;
  });
  state.receiveWithSdk.mockImplementation((options: { onComplete: (content: { bytes: Uint8Array }) => Promise<void> }) => {
    void options.onComplete({ bytes: new TextEncoder().encode("opened") });
  });
  state.receive.mockResolvedValue({
    identity: { kind: "receiver", holderDid: "did:key:z6MkReceiver", custody: "persistent", origin: "https://share.tinycloud.xyz" },
    shareId: "share-500",
    metadata: {
      protocol: "tinycloud-share",
      version: 1,
      shareId: "share-500",
      origin: "https://share.tinycloud.xyz",
      target: { kind: "email", origin: "https://node.example", nodeAudience: "did:key:z6MkEnforcer", spaceId: "space-1" },
      resource: { kind: "exact", path: "shares/share-500/report.md" },
      actions: ["read"],
      expiresAt: "2026-08-08T20:00:00Z",
      display: { filename: "report.md" },
    },
    get: (...args: unknown[]) => state.get(...args),
    importInto: (...args: unknown[]) => state.importInto(...args),
  });
  state.get.mockResolvedValue({
    bytes: new TextEncoder().encode("opened"),
    filename: "report.md",
    mediaType: "text/plain",
    senderDid: "did:key:z6MkSender",
    shareId: "share-500",
    byteDigest: "digest",
    receivedAt: "2026-08-07T20:00:00Z",
  });
  state.importInto.mockResolvedValue({ status: "imported", path: "files-for-you/v1/content/share-500/report.md", byteDigest: "digest" });
});

describe("first-class accountless receiver", () => {
  it("routes through the reusable accountless reader with zero OpenKey calls", async () => {
    await import("../src/main.js");
    await vi.waitFor(() => expect(state.presented).toHaveLength(1));

    expect(state.receiveWithSdk).toHaveBeenCalledWith(
      expect.objectContaining({
        root: document.getElementById("viewer"),
        shareUrl: "https://share.tinycloud.xyz/s/inline#v=2&p=test",
      }),
    );
    expect(state.receive).not.toHaveBeenCalled();
    expect(state.authenticate).not.toHaveBeenCalled();
    expect(state.resolve).toHaveBeenCalledTimes(1);
    expect(new TextDecoder().decode((state.presented[0]!.result as { contentBytes: Uint8Array }).contentBytes)).toBe("opened");

    expect(state.createAccountClient).not.toHaveBeenCalled();
  });

  it("drops a legacy receiver key record and its credentials before the receiver starts, after the launch scrub", async () => {
    window.sessionStorage.setItem("tinycloud.share.receiver-session.v1", JSON.stringify({ jwk: { d: "legacy" } }));
    window.sessionStorage.setItem("tinycloud.share.receiver-credentials.v1", "{}");
    window.sessionStorage.setItem("unrelated", "kept");
    const read = Storage.prototype.getItem;
    const spy = vi.spyOn(Storage.prototype, "getItem").mockImplementation(function (this: Storage, key: string) {
      state.events.push(`get ${key}`);
      return read.call(this, key);
    });
    const seen: (string | null)[] = [];
    state.receiveWithSdk.mockImplementation((options: { onComplete: (content: { bytes: Uint8Array }) => Promise<void> }) => {
      spy.mockRestore();
      seen.push(window.sessionStorage.getItem("tinycloud.share.receiver-session.v1"), window.sessionStorage.getItem("tinycloud.share.receiver-credentials.v1"));
      void options.onComplete({ bytes: new Uint8Array([1]) });
    });
    await import("../src/main.js");
    await vi.waitFor(() => expect(state.receiveWithSdk).toHaveBeenCalledTimes(1));
    expect(seen).toEqual([null, null]);
    expect(window.sessionStorage.getItem("unrelated")).toBe("kept");
    expect(state.events.slice(0, 2)).toEqual(["scrub", "get tinycloud.share.receiver-session.v1"]);
  });

  it("keeps credentials issued to the current key when no legacy key record exists", async () => {
    window.sessionStorage.setItem("tinycloud.share.receiver-credentials.v1", "{\"current\":true}");
    const seen: (string | null)[] = [];
    state.receiveWithSdk.mockImplementation((options: { onComplete: (content: { bytes: Uint8Array }) => Promise<void> }) => {
      seen.push(window.sessionStorage.getItem("tinycloud.share.receiver-credentials.v1"));
      void options.onComplete({ bytes: new Uint8Array([1]) });
    });
    await import("../src/main.js");
    await vi.waitFor(() => expect(state.receiveWithSdk).toHaveBeenCalledTimes(1));
    expect(seen).toEqual(["{\"current\":true}"]);
  });

  it("stops with a browser message when no signing key can be created", async () => {
    vi.spyOn(console, "debug").mockImplementation(() => undefined);
    state.receiveWithSdk.mockRejectedValueOnce(Object.assign(new Error("This browser cannot create a signing key for this page"), { name: "ShareReceiverKeyUnavailableError" }));
    await import("../src/main.js");
    await vi.waitFor(() => expect(state.invalid).toHaveBeenCalledTimes(1));
    expect(state.invalid.mock.calls[0]![1]).toBe("This browser can’t create the private key needed to open this file. Nothing was opened. Open the link in a current version of Chrome, Edge, Firefox or Safari.");
    expect(state.presented).toHaveLength(0);
  });

  it("asks the recipient to open the link again when the page's key session has ended", async () => {
    vi.spyOn(console, "debug").mockImplementation(() => undefined);
    state.receiveWithSdk.mockRejectedValueOnce(Object.assign(new Error("This receiver session has ended"), { name: "ShareReceiverSessionEndedError" }));
    await import("../src/main.js");
    await vi.waitFor(() => expect(state.invalid).toHaveBeenCalledTimes(1));
    expect(state.invalid.mock.calls[0]![1]).toBe("Your verification on this page has ended. Open the link from your email again and verify again.");
  });

  it("still opens the share when site storage is blocked and reading sessionStorage throws", async () => {
    const descriptor = Object.getOwnPropertyDescriptor(window, "sessionStorage")!;
    Object.defineProperty(window, "sessionStorage", { configurable: true, get: () => { throw new DOMException("The operation is insecure.", "SecurityError"); } });
    try {
      await import("../src/main.js");
      await vi.waitFor(() => expect(state.presented).toHaveLength(1));
      expect(state.receiveWithSdk).toHaveBeenCalledTimes(1);
      expect(state.invalid).not.toHaveBeenCalled();
    } finally {
      Object.defineProperty(window, "sessionStorage", descriptor);
    }
  });

  it("keeps remote receiver response details out of console telemetry", async () => {
    const debug = vi.spyOn(console, "debug").mockImplementation(() => undefined);
    const errorLog = vi.spyOn(console, "error").mockImplementation(() => undefined);
    const warn = vi.spyOn(console, "warn").mockImplementation(() => undefined);
    const log = vi.spyOn(console, "log").mockImplementation(() => undefined);
    state.receiveWithSdk.mockRejectedValueOnce(
      new Error("delegate rejected: tc500-secret-marker"),
    );

    await import("../src/main.js");
    await vi.waitFor(() => expect(state.invalid).toHaveBeenCalledTimes(1));

    expect(debug).toHaveBeenCalledWith("tinycloud share: recipient request failed");
    expect(JSON.stringify([
      ...debug.mock.calls,
      ...errorLog.mock.calls,
      ...warn.mock.calls,
      ...log.mock.calls,
    ])).not.toContain("tc500-secret-marker");
  });
});
