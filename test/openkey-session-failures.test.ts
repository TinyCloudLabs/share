import { afterEach, describe, expect, it, vi } from "vitest";
import { authFailureMessage, senderFailureKind } from "../src/share/sender-failure.js";

/**
 * TC-335, the half `auth-wall-vocabulary.test.ts` mocks away: every throw in
 * `authenticateWithOpenKey` must carry a `kind`, because that tag is the only
 * thing the sign-in wall renders. An untagged throw silently degrades to the
 * generic message and its detail is lost, so the tags are pinned here.
 */

const ADDRESS = "0x1111111111111111111111111111111111111111";
const NONCE = "abcdefghijklmnopqrstuvwxyz012345";

vi.mock("@openkey/sdk", () => ({
  OpenKey: class {
    async connect(): Promise<{ address: string; keyId: string }> { return { address: ADDRESS, keyId: "key-1" }; }
    async signMessage(): Promise<{ address: string; signature: string }> { return { address: ADDRESS, signature: "0xsignature" }; }
  },
  OpenKeyProvider: class {},
}));

vi.mock("@tinycloud/web-sdk", () => ({ TinyCloudWeb: class {} }));

afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); });

/** `responses` is keyed by the endpoint path the session hits, in order. */
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

async function rejection(responses: Record<string, Response>): Promise<unknown> {
  stubEndpoints(responses);
  const { authenticateWithOpenKey } = await import("../src/share/openkey-session.js");
  return await authenticateWithOpenKey(() => undefined).then(() => undefined, (error: unknown) => error);
}

describe("openkey sign-in failure tagging (TC-335)", () => {
  it("tags an account that does not control a sharing space as `account`, not raw text", async () => {
    const error = await rejection({ "/auth/openkey/nonce": nonceOk(), "/api/share/auth/openkey": new Response(null, { status: 403 }) });

    expect(senderFailureKind(error)).toBe("account");
    expect(authFailureMessage(error)).toBe("Your account isn't set up for sharing yet. Contact support.");
    // The detail still names the real condition — for the log, never the wall.
    expect((error as Error).message).toContain("authorized sharing space");
    expect(authFailureMessage(error)).not.toContain("space");
  });

  it("tags a rejected sign-in challenge endpoint as `signInService`", async () => {
    const error = await rejection({ "/auth/openkey/nonce": new Response(null, { status: 503 }) });

    expect(senderFailureKind(error)).toBe("signInService");
    expect(authFailureMessage(error)).toBe("TinyCloud is temporarily unavailable. Try signing in again shortly.");
  });

  it("tags a malformed sign-in challenge as `signInService`", async () => {
    const error = await rejection({ "/auth/openkey/nonce": new Response(JSON.stringify({ nonce: "short", expiresAt: "not-a-date" }), { status: 200, headers: { "content-type": "application/json" } }) });

    expect(senderFailureKind(error)).toBe("signInService");
  });

  it("leaves no untagged throw on the sign-in path", async () => {
    const { readFile } = await import("node:fs/promises");
    const { resolve } = await import("node:path");
    const source = await readFile(resolve(process.cwd(), "src/share/openkey-session.ts"), "utf8");
    const signIn = source.slice(source.indexOf("export async function authenticateWithOpenKey"), source.indexOf("function writePermissions"));
    expect(signIn).not.toContain("throw new Error(");
    expect(signIn).toContain("throw fail(");
  });
});
