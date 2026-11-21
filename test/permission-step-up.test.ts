import { afterEach, describe, expect, it, vi } from "vitest";
import { TinyCloudWeb } from "@tinycloud/web-sdk";
import { requestInOpenKey } from "../src/share/permission-step-up.js";

afterEach(() => { document.body.replaceChildren(); });

/** The published SDK's own `requestPermissions`, with only its node and its grant step supplied (as in the permission-dialog contract test). */
function sdkClient(grant: (permissions: unknown, options: unknown) => Promise<readonly unknown[]>): TinyCloudWeb {
  const client = Object.create(TinyCloudWeb.prototype) as TinyCloudWeb;
  Object.assign(client, {
    _manifest: { app_id: "xyz.tinycloud.share", name: "TinyCloud Share" },
    config: { ui: false },
    session: () => undefined,
    ensureNode: async () => ({ did: "did:pkh:eip155:1:0x0000000000000000000000000000000000000001", hasRuntimePermissions: () => false }),
    uiClient: { promptScope: undefined },
    _testHooks: { grantPermissions: grant },
  });
  return client;
}

describe("asking OpenKey through the SDK with its own windows turned off", () => {
  it("reaches the grant with the requested permission and lifetime, and reports approval", async () => {
    const grant = vi.fn(async () => []);
    const permissions = [{ service: "tinycloud.encryption", path: "urn:tinycloud:encryption:did:pkh:eip155:1:0xabc:default", actions: ["decrypt"], skipPrefix: true }];
    await expect(requestInOpenKey(sdkClient(grant), permissions, { expiryMs: 3_600_000 })).resolves.toBe(true);
    expect(grant).toHaveBeenCalledTimes(1);
    expect(grant).toHaveBeenCalledWith(permissions, { expiryMs: 3_600_000 });
    // No SDK window was put up for it.
    expect(document.querySelector("dialog")).toBeNull();
  });

  it("is needed: asked directly, the SDK with its windows off answers no before OpenKey is reached", async () => {
    const grant = vi.fn(async () => []);
    const warn = vi.spyOn(console, "warn").mockImplementation(() => undefined);
    const result = await sdkClient(grant).requestPermissions([{ service: "tinycloud.encryption", path: "x", actions: ["decrypt"], skipPrefix: true }], { expiryMs: 3_600_000 });
    warn.mockRestore();
    expect(result.approved).toBe(false);
    expect(grant).not.toHaveBeenCalled();
  });

  it("reports a grant that fails to complete as an error, not an approval", async () => {
    const grant = vi.fn(async () => { throw new Error("OpenKey window closed"); });
    await expect(requestInOpenKey(sdkClient(grant), [{ service: "tinycloud.encryption", path: "x", actions: ["decrypt"], skipPrefix: true }], { expiryMs: 3_600_000 })).rejects.toThrow("OpenKey window closed");
  });
});
