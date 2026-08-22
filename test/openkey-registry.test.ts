// @vitest-environment jsdom
import { beforeEach, describe, expect, it, vi } from "vitest";

const state = vi.hoisted(() => ({ config: undefined as Record<string, unknown> | undefined }));

vi.mock("@openkey/sdk", () => ({
  OpenKey: class {},
  OpenKeyProvider: class { constructor(..._args: unknown[]) {} },
}));

vi.mock("@tinycloud/sdk-core", () => ({
  createOpenKeyCallbackSigningStrategy: () => ({ handler: async () => ({ approved: true, signature: "0xsigned" }) }),
}));

vi.mock("@tinycloud/web-sdk", () => ({
  TinyCloudWeb: class {
    constructor(config: Record<string, unknown>) { state.config = config; }
    async signIn(): Promise<void> {}
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
        tinycloudSigningOptions: () => ({ endpoint: "https://openkey.example/sign", token: "token" }),
        signMessage: async () => ({ address: "0x1234567890abcdef1234567890abcdef12345678", signature: "0xsigned" }),
      },
    } as never, {
      shareOrigin: "https://share.tinycloud.xyz",
      registryOrigin: "https://registry.tinycloud.xyz",
    } as never, () => undefined);

    expect(state.config).toMatchObject({
      tinycloudRegistryUrl: "https://registry.tinycloud.xyz",
      tinycloudFallbackHosts: null,
      autoDiscoverLocalNode: false,
    });
    expect(state.config).not.toHaveProperty("tinycloudHosts");
  });
});
