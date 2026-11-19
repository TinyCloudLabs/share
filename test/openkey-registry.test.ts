// @vitest-environment jsdom
import { beforeEach, describe, expect, it, vi } from "vitest";

const state = vi.hoisted(() => ({ config: undefined as Record<string, unknown> | undefined }));

vi.mock("@openkey/sdk", () => ({
  OpenKey: class {},
  OpenKeyProvider: class { constructor(..._args: unknown[]) {} },
}));

vi.mock("@tinycloud/web-sdk", () => ({
  TinyCloudWeb: class {
    constructor(config: Record<string, unknown>) { state.config = config; }
    async signIn(): Promise<{ address: string; siwe: string }> { return { address: "0x1234567890abcdef1234567890abcdef12345678", siwe: "" }; }
    async ensureOwnedSpaceHosted(): Promise<string> { return "applications"; }
  },
}));

describe("Share owner node discovery", () => {
  beforeEach(() => { state.config = undefined; });

  it("resolves the signed-in owner's TinyCloud through the public registry", async () => {
    const { createTinyCloudClient } = await import("../src/share/openkey-session.js");
    await createTinyCloudClient({
      address: "0x1234567890abcdef1234567890abcdef12345678",
      auth: { keyId: "key-1" },
      openkey: {
        signMessage: async () => ({ address: "0x1234567890abcdef1234567890abcdef12345678", signature: "0xsigned" }),
      },
    } as never, {
      shareOrigin: "https://share.tinycloud.xyz",
      senderBootstrapNodeOrigin: "https://tee.node.tinycloud.xyz",
      registryOrigin: "https://registry.tinycloud.xyz",
    } as never, () => undefined);

    expect(state.config).toMatchObject({
      tinycloudRegistryUrl: "https://registry.tinycloud.xyz",
      tinycloudFallbackHosts: ["https://tee.node.tinycloud.xyz"],
      autoDiscoverLocalNode: false,
    });
    expect(state.config).not.toHaveProperty("tinycloudHosts");
  });
});
