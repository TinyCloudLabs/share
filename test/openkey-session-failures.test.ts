import { afterEach, describe, expect, it, vi } from "vitest";
import { authFailureMessage, senderFailureKind } from "../src/share/sender-failure.js";

const ADDRESS = "0x1111111111111111111111111111111111111111";
const NONCE = "abcdefghijklmnopqrstuvwxyz012345";
const SIWE = "tinycloud-session-siwe";

const state = vi.hoisted(() => ({
  token: "openkey-session-token.cookie-signature" as string | null,
  callbackOptions: [] as Record<string, unknown>[],
  configs: [] as Record<string, unknown>[],
  signMessage: vi.fn(async () => ({ address: ADDRESS, signature: "0xsignature" })),
  automaticSign: vi.fn(async () => ({ approved: true, signature: "0xautomatic" })),
  signIn: vi.fn(async () => ({ siwe: SIWE, signature: "0xtinycloud" })),
  signOut: vi.fn(async () => undefined),
  ensureOwnedSpaceHosted: vi.fn(async () => "tinycloud:pkh:eip155:1:0x1:account"),
}));

vi.mock("@openkey/sdk", () => ({
  OpenKey: class {
    async connect(): Promise<{ address: string; keyId: string }> { return { address: ADDRESS, keyId: "key-1" }; }
    getSessionToken(): string | null { return state.token; }
    tinycloudSigningOptions(): { endpoint: string; token: string | null } { return { endpoint: "https://api.openkey.so/api/delegate/sign", token: state.token }; }
    signMessage = state.signMessage;
  },
  OpenKeyProvider: class {},
}));

vi.mock("@tinycloud/sdk-core", () => ({
  createOpenKeyCallbackSigningStrategy: (options: Record<string, unknown>) => {
    state.callbackOptions.push(options);
    return { type: "callback", openKeyAutoSign: true, handler: state.automaticSign };
  },
}));

vi.mock("@tinycloud/web-sdk", () => ({
  TinyCloudWeb: class {
    constructor(config: Record<string, unknown>) { state.configs.push(config); }
    signIn = state.signIn;
    signOut = state.signOut;
    ensureOwnedSpaceHosted = state.ensureOwnedSpaceHosted;
  },
}));

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  state.token = "openkey-session-token.cookie-signature";
  state.callbackOptions.length = 0;
  state.configs.length = 0;
  state.signMessage.mockClear();
  state.automaticSign.mockClear();
  state.signIn.mockClear();
  state.signOut.mockClear();
  state.ensureOwnedSpaceHosted.mockClear();
});

function stubEndpoints(responses: Record<string, Response>): void {
  vi.stubGlobal("fetch", vi.fn(async (url: string | URL | Request) => {
    const path = String(url);
    const match = Object.keys(responses).find((key) => path.includes(key));
    if (match === undefined) throw new Error(`unexpected fetch: ${path}`);
    return responses[match]!;
  }));
}

function nonceOk(): Response {
  return new Response(JSON.stringify({ nonce: NONCE, expiresAt: new Date(Date.now() + 60_000).toISOString() }), { status: 200, headers: { "content-type": "application/json" } });
}

async function connectedSession() {
  const { authenticateWithOpenKey } = await import("../src/share/openkey-session.js");
  return authenticateWithOpenKey(() => undefined);
}

async function clientRejection(responses: Record<string, Response>): Promise<unknown> {
  stubEndpoints(responses);
  const session = await connectedSession();
  const { createTinyCloudClient } = await import("../src/share/openkey-session.js");
  return createTinyCloudClient(session, { shareOrigin: "https://share.example", nodeOrigin: "https://node.example" } as never, [], () => undefined).then(() => undefined, (error: unknown) => error);
}

describe("consolidated OpenKey sign-in", () => {
  it("fails closed when OpenKey does not return a delegated signing token", async () => {
    state.token = null;
    const error = await connectedSession().then(() => undefined, (failure: unknown) => failure);
    expect(senderFailureKind(error)).toBe("signInService");
  });

  it("tags a rejected Share nonce endpoint as `signInService`", async () => {
    const error = await clientRejection({ "/auth/openkey/nonce": new Response(null, { status: 503 }) });
    expect(senderFailureKind(error)).toBe("signInService");
    expect(authFailureMessage(error)).toBe("TinyCloud is temporarily unavailable. Try signing in again shortly.");
  });

  it("tags a malformed Share nonce as `signInService`", async () => {
    const error = await clientRejection({ "/auth/openkey/nonce": new Response(JSON.stringify({ nonce: "short", expiresAt: "not-a-date" }), { status: 200, headers: { "content-type": "application/json" } }) });
    expect(senderFailureKind(error)).toBe("signInService");
  });

  it("tags a rejected consolidated session proof as `account`", async () => {
    const error = await clientRejection({ "/auth/openkey/nonce": nonceOk(), "/api/share/auth/openkey": new Response(null, { status: 403 }) });
    expect(senderFailureKind(error)).toBe("account");
    expect(authFailureMessage(error)).toBe("Your account isn't set up for sharing yet. Contact support.");
  });

  it("uses one TinyCloud sign-in, reuses its SIWE for Share auth, and never signs out to bootstrap", async () => {
    const fetcher = vi.fn(async (url: string | URL | Request, init?: RequestInit) => String(url).includes("/nonce")
      ? nonceOk()
      : new Response(JSON.stringify({ ok: true, body: JSON.parse(String(init?.body)) }), { status: 200, headers: { "content-type": "application/json" } }));
    vi.stubGlobal("fetch", fetcher);
    const session = await connectedSession();
    const { createTinyCloudClient } = await import("../src/share/openkey-session.js");
    await createTinyCloudClient(session, { shareOrigin: "https://share.example", nodeOrigin: "https://node.example" } as never, [], () => undefined);

    expect(state.signIn).toHaveBeenCalledTimes(1);
    expect(state.signIn).toHaveBeenCalledWith({ nonce: NONCE });
    expect(state.signOut).not.toHaveBeenCalled();
    expect(state.ensureOwnedSpaceHosted).toHaveBeenCalledOnce();
    expect(JSON.parse(String(fetcher.mock.calls[1]?.[1]?.body))).toEqual({ message: SIWE, signature: "0xtinycloud" });
    expect(state.configs[0]).toMatchObject({
      autoBootstrapAccount: false,
      persistSession: false,
      sessionExpirationMs: 60 * 60 * 1000,
      siweConfig: { statement: "Sign in to TinyCloud Share." },
    });
    expect(state.callbackOptions[0]).toMatchObject({
      endpoint: "https://api.openkey.so/api/delegate/sign",
      token: "openkey-session-token",
      keyId: "key-1",
      credentials: "omit",
    });

    const strategy = state.configs[0]?.signStrategy as { handler(request: { purpose?: string; message: string }): Promise<unknown> };
    await strategy.handler({ purpose: "sign-in", message: "manifest session" });
    await strategy.handler({ purpose: "bootstrap-host", message: "host account" });
    expect(state.signMessage).toHaveBeenCalledTimes(1);
    expect(state.automaticSign).toHaveBeenCalledTimes(1);
  });
});
