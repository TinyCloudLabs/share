// @vitest-environment jsdom
import { beforeEach, describe, expect, it, vi } from "vitest";

const created = vi.hoisted(() => ({ options: undefined as undefined | { shareReceiver?: { sessionStorage?: Storage } } }));

vi.mock("@tinycloud/web-sdk", () => ({
  TinyCloudWeb: { create: async (options: typeof created.options) => { created.options = options; return {}; } },
}));

const config = {
  version: "tinycloud.share/config-v2",
  shareOrigin: "https://share.tinycloud.xyz",
  senderBootstrapNodeOrigin: "https://tee.node.tinycloud.xyz",
  registryOrigin: "https://registry.tinycloud.xyz",
  credentialsOrigin: "https://credentials.example",
  accountlessReceiverEnabled: true,
} as never;

beforeEach(() => {
  window.sessionStorage.clear();
  window.localStorage.clear();
  created.options = undefined;
});

describe("receiver key and credential storage", () => {
  it("keeps the receiver's records in page memory, never in session or local storage", async () => {
    const { createShareReceiverClient } = await import("../src/share/receiver.js");
    await createShareReceiverClient(config);
    const storage = created.options?.shareReceiver?.sessionStorage;
    expect(storage).toBeDefined();
    expect(storage).not.toBe(window.sessionStorage);
    storage!.setItem("tinycloud.share.receiver-session.v1", JSON.stringify({ jwk: { d: "private" } }));
    expect(storage!.getItem("tinycloud.share.receiver-session.v1")).toContain("private");
    expect(window.sessionStorage.length).toBe(0);
    expect(window.localStorage.length).toBe(0);

    // A second page load starts with nothing: the recipient verifies again.
    await createShareReceiverClient(config);
    expect(created.options?.shareReceiver?.sessionStorage?.getItem("tinycloud.share.receiver-session.v1")).toBeNull();
  });

  it("purges receiver records earlier builds left in session storage and nothing else", async () => {
    const { purgeLegacyReceiverStorage } = await import("../src/email-share/receiver-storage.js");
    window.sessionStorage.setItem("tinycloud.share.receiver-session.v1", "{}");
    window.sessionStorage.setItem("tinycloud.share.receiver-credentials.v1", "{}");
    window.sessionStorage.setItem("unrelated", "kept");
    purgeLegacyReceiverStorage(window.sessionStorage);
    expect(Object.keys({ ...window.sessionStorage })).toEqual(["unrelated"]);
    expect(() => purgeLegacyReceiverStorage({ removeItem: () => { throw new DOMException("denied", "SecurityError"); } })).not.toThrow();
  });
});
