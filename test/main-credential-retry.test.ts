import { beforeEach, describe, expect, it, vi } from "vitest";

const state = vi.hoisted(() => ({
  authenticate: vi.fn(),
  createAccountClient: vi.fn(),
  receive: vi.fn(),
  get: vi.fn(),
  importInto: vi.fn(),
  resolve: vi.fn(),
  presented: [] as { result: unknown; options: Record<string, unknown> }[],
  resolved: undefined as unknown,
}));

vi.mock("../src/email-share/url.js", () => ({
  captureAndScrubLaunch: () => ({ shareHref: "https://share.tinycloud.xyz/s/test#k=secret" }),
}));

vi.mock("../src/email-share/view.js", () => ({
  appendRecipientForgetAction: () => undefined,
  renderRecipientInvalid: () => undefined,
  renderRecipientLoading: () => undefined,
  renderRecipientState: () => undefined,
}));

vi.mock("../src/email-share/claim.js", () => ({
  createHolder: async () => undefined,
  createClaimController: () => ({ state: { state: "idle" }, subscribe: () => undefined }),
}));

vi.mock("../src/email-share/config.js", () => ({
  loadSharePublicConfig: async () => ({
    shareOrigin: "https://share.tinycloud.xyz",
    registryOrigin: "https://registry.tinycloud.xyz",
    nodeOrigin: "https://node.example",
    credentialsOrigin: "https://credentials.example",
    accountlessReceiverEnabled: true,
    nodeAudience: "did:web:node.example",
    enforcerDid: "did:web:node.example",
    nodeInvitationKid: "did:web:node.example#key-1",
    nodeInvitationPublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
  }),
  trustedNodeFromConfig: () => ({ did: "did:web:node.example" }),
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
  state.get.mockReset();
  state.importInto.mockReset();
  state.resolve.mockReset();
  state.presented.length = 0;
  const envelope = {
    version: 3,
    recipientMatcher: { kind: "exactEmail", value: "reader@example.com" },
    display: { filename: "report.md" },
    metadata: { filename: "report.md", mediaType: "text/plain" },
  };
  state.resolved = {
    state: "policy-v2-claim-required",
    envelope,
    policy: { schema: "xyz.tinycloud.policy/policy/v2" },
    shareCid: "bafkreicredentialshare",
  };
  state.resolve.mockResolvedValue(state.resolved);
  state.receive.mockResolvedValue({
    identity: { kind: "receiver", holderDid: "did:key:z6MkReceiver", custody: "session", origin: "https://share.tinycloud.xyz" },
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

describe("TC-500 first-class accountless receiver", () => {
  it("renders through share.receive with zero OpenKey calls, then signs in only for explicit save", async () => {
    await import("../src/main.js");
    await vi.waitFor(() => expect(state.presented).toHaveLength(1));

    expect(state.receive).toHaveBeenCalledWith(
      "https://share.tinycloud.xyz/s/test#k=secret",
      expect.objectContaining({ identity: "auto", interaction: { kind: "inline", mountTarget: document.getElementById("viewer") } }),
    );
    expect(state.authenticate).not.toHaveBeenCalled();
    expect(state.resolve).not.toHaveBeenCalled();
    expect(new TextDecoder().decode((state.presented[0]!.result as { contentBytes: Uint8Array }).contentBytes)).toBe("opened");

    const accountClient = { session: () => ({}) };
    state.authenticate.mockResolvedValue({});
    state.createAccountClient.mockResolvedValue(accountClient);
    const save = state.presented[0]!.options.saveToTinyCloud as () => Promise<void>;
    await save();

    expect(state.authenticate).toHaveBeenCalledTimes(1);
    expect(state.importInto).toHaveBeenCalledWith(accountClient, {
      namespace: "files-for-you",
      filename: "report.md",
    });
  });
});
