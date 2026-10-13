// @vitest-environment jsdom
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { CallbackStrategy } from "@tinycloud/sdk-core";
import { authenticateWithOpenKey, createTinyCloudClient } from "../src/share/openkey-session.js";

const SENDER = "0x1234567890abcdef1234567890abcdef12345678";

const state = vi.hoisted(() => ({
  config: undefined as Record<string, unknown> | undefined,
  signed: [] as Array<{ message: string; keyId?: string }>,
  signer: "",
}));

// Production OpenKey since TC-688: connect() answers without a session token
// and getSessionToken() is always null for embedding pages.
vi.mock("@openkey/sdk", () => ({
  OpenKey: class {
    async connect() { return { address: SENDER, keyId: "key-1", keyType: "MANAGED" }; }
    getSessionToken() { return null; }
    tinycloudSigningOptions() { return { endpoint: "https://api.openkey.so/api/delegate/sign", token: null }; }
    async signMessage(request: { message: string; keyId?: string }) {
      state.signed.push(request);
      return { address: state.signer, signature: "0xsigned" };
    }
  },
  OpenKeyProvider: class { constructor(..._args: unknown[]) {} },
}));

vi.mock("@tinycloud/web-sdk", () => ({
  TinyCloudWeb: class {
    constructor(config: Record<string, unknown>) { state.config = config; }
    async signIn(): Promise<void> {}
    async ensureOwnedSpaceHosted(): Promise<string> { return "account"; }
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
    vi.stubGlobal("fetch", vi.fn(() => Promise.reject(new Error("Share must not call OpenKey's signer directly"))));
  });

  it("signs in when OpenKey gives the page no session token", async () => {
    await expect(authenticateWithOpenKey(() => undefined)).resolves.toMatchObject({ address: SENDER });
  });

  it("asks the sender's OpenKey widget for sign-in, bootstrap and hosting signatures", async () => {
    const strategy = await signedInStrategy();
    const purposes = ["sign-in", "bootstrap-session", "bootstrap-host"] as const;
    for (const purpose of purposes) {
      await expect(strategy.handler({ address: SENDER, chainId: 1, message: `siwe:${purpose}`, type: "siwe", purpose }))
        .resolves.toEqual({ approved: true, signature: "0xsigned" });
    }
    expect(state.signed).toEqual(purposes.map((purpose) => ({ message: `siwe:${purpose}`, keyId: "key-1" })));
    expect(fetch).not.toHaveBeenCalled();
  });

  it("refuses a signature OpenKey made with a different account", async () => {
    const strategy = await signedInStrategy();
    state.signer = "0x0000000000000000000000000000000000000001";
    await expect(strategy.handler({ address: SENDER, chainId: 1, message: "siwe:host", type: "siwe", purpose: "bootstrap-host" }))
      .resolves.toMatchObject({ approved: false });
  });
});
