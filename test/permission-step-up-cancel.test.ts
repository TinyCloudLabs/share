import { beforeEach, describe, expect, it, vi } from "vitest";
import { requestInOpenKey } from "../src/share/permission-step-up.js";

const observed = vi.hoisted(() => ({ failure: undefined as "cancelled" | "timeout" | "wrong-account" | undefined }));
vi.mock("../src/share/openkey-session.js", () => ({ takeWalletApprovalFailure: () => observed.failure }));

const PERMISSIONS = [{ service: "tinycloud.encryption", path: "urn:tinycloud:encryption:x:default", actions: ["decrypt"], skipPrefix: true }];

beforeEach(() => { observed.failure = undefined; });

describe("a cancelled OpenKey approval", () => {
  it("is a no, not an error, when OpenKey says the person cancelled", async () => {
    observed.failure = "cancelled";
    const tinycloud = { requestPermissions: vi.fn(async () => { throw { code: "USER_CANCELLED" }; }) };
    await expect(requestInOpenKey(tinycloud as never, PERMISSIONS)).resolves.toBe(false);
  });

  it("stays an error for a timeout, a wrong account, or a failure OpenKey did not classify", async () => {
    for (const failure of ["timeout", "wrong-account", undefined] as const) {
      observed.failure = failure;
      const tinycloud = { requestPermissions: vi.fn(async () => { throw new Error("boom"); }) };
      await expect(requestInOpenKey(tinycloud as never, PERMISSIONS)).rejects.toThrow("boom");
    }
  });

  it("an approval is still an approval", async () => {
    const tinycloud = { requestPermissions: vi.fn(async () => ({ approved: true })) };
    await expect(requestInOpenKey(tinycloud as never, PERMISSIONS)).resolves.toBe(true);
  });
});
