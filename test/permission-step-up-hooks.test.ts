import { beforeEach, describe, expect, it, vi } from "vitest";
import { requestInOpenKey } from "../src/share/permission-step-up.js";

const observed = vi.hoisted(() => ({ failure: undefined as "cancelled" | "timeout" | "wrong-account" | undefined }));
vi.mock("../src/share/openkey-session.js", () => ({ takeWalletApprovalFailure: () => observed.failure }));

const PERMISSIONS = [{ service: "tinycloud.encryption", path: "urn:tinycloud:encryption:x:default", actions: ["decrypt"], skipPrefix: true }];

beforeEach(() => { observed.failure = undefined; });

/** A client whose `requestPermissions` runs `body` with the SDK's window handler as it is while the request is open. */
function client(body: (handler: unknown) => Promise<{ approved: boolean }>, options: { held?: boolean; hooks?: unknown } = {}) {
  const tinycloud: { _testHooks?: unknown; requestPermissions: ReturnType<typeof vi.fn>; hasPermissions: ReturnType<typeof vi.fn> } = {
    requestPermissions: vi.fn(async () => body(Reflect.get(Object(tinycloud._testHooks), "showModal"))),
    hasPermissions: vi.fn(() => options.held ?? false),
  };
  if ("hooks" in options) tinycloud._testHooks = options.hooks;
  return tinycloud;
}

describe("the SDK's window handler", () => {
  it("answers the SDK's question while the request is open, then is put back as it was (another handler present)", async () => {
    const other = vi.fn();
    const original = { other, showModal: undefined };
    const tinycloud = client(async (showModal) => ({ approved: await (showModal as () => Promise<{ approved: boolean }>)().then((answer) => answer.approved) }), { hooks: original });
    await expect(requestInOpenKey(tinycloud as never, PERMISSIONS)).resolves.toBe(true);
    expect(tinycloud._testHooks).toBe(original);
    expect(Reflect.get(Object(tinycloud._testHooks), "other")).toBe(other);
  });

  it("is put back to none when there was none", async () => {
    const tinycloud = client(async () => ({ approved: true }));
    expect("_testHooks" in tinycloud).toBe(false);
    await requestInOpenKey(tinycloud as never, PERMISSIONS);
    expect(tinycloud._testHooks).toBeUndefined();
  });

  it("is put back when the request fails, and when it is cancelled", async () => {
    const original = { keep: true };
    const failing = client(async () => { throw new Error("boom"); }, { hooks: original });
    await expect(requestInOpenKey(failing as never, PERMISSIONS)).rejects.toThrow("boom");
    expect(failing._testHooks).toBe(original);

    observed.failure = "cancelled";
    const cancelled = client(async () => { throw { code: "USER_CANCELLED" }; });
    await expect(requestInOpenKey(cancelled as never, PERMISSIONS)).resolves.toBe(false);
    expect(cancelled._testHooks).toBeUndefined();
  });
});

describe("a cancelled approval", () => {
  it("is declined when nothing was granted", async () => {
    observed.failure = "cancelled";
    const tinycloud = client(async () => { throw { code: "USER_CANCELLED" }; }, { held: false });
    await expect(requestInOpenKey(tinycloud as never, PERMISSIONS)).resolves.toBe(false);
    expect(tinycloud.hasPermissions).toHaveBeenCalledWith(PERMISSIONS);
  });

  it("is reported as held, not declined, when the SDK had already activated the grant before it rejected", async () => {
    observed.failure = "cancelled";
    const tinycloud = client(async () => { throw { code: "USER_CANCELLED" }; }, { held: true });
    await expect(requestInOpenKey(tinycloud as never, PERMISSIONS)).resolves.toBe(true);
  });

  it("never turns a failure that is not a cancel into an approval, even when the permissions are held", async () => {
    for (const failure of ["timeout", "wrong-account", undefined] as const) {
      observed.failure = failure;
      const tinycloud = client(async () => { throw new Error("boom"); }, { held: true });
      await expect(requestInOpenKey(tinycloud as never, PERMISSIONS)).rejects.toThrow("boom");
      expect(tinycloud.hasPermissions).not.toHaveBeenCalled();
    }
  });
});
