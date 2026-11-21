import { describe, expect, it, vi } from "vitest";
import { defaultEncryptionNetworkForOwner } from "@tinycloud/share-sdk";
import { createNetworkSetup } from "../src/share/network-setup.js";
import { NetworkSetupDeclinedError } from "../src/share/network-setup-declined.js";
import { NETWORK_SETUP } from "../src/share/history-copy.js";
import { senderFailureMessage, SENDER_FAILURE } from "../src/share/sender-failure.js";

const ADDRESS = "0xAbCdEf1234567890aBcDeF1234567890abCDef12";
const NETWORK_ID = defaultEncryptionNetworkForOwner({ address: ADDRESS });

interface Calls { readonly order: string[]; }

function client(options: { exists: boolean; approve?: boolean }) {
  const calls: Calls = { order: [] };
  const getEncryptionNetwork = vi.fn(async () => { calls.order.push("get"); return options.exists ? { id: NETWORK_ID } : null; });
  const requestPermissions = vi.fn(async () => { calls.order.push("request"); return { approved: options.approve ?? true }; });
  const ensureEncryptionNetwork = vi.fn(async () => { calls.order.push("ensure"); return { id: NETWORK_ID }; });
  return { calls, getEncryptionNetwork, requestPermissions, ensureEncryptionNetwork };
}

describe("the one-time encryption setup", () => {
  it("asks nothing of an account whose network exists", async () => {
    const tinycloud = client({ exists: true });
    const onStatus = vi.fn();
    const setup = createNetworkSetup(tinycloud as never, { address: ADDRESS }, onStatus);
    await setup.ensure();
    expect(tinycloud.getEncryptionNetwork).toHaveBeenCalledWith(NETWORK_ID);
    expect(tinycloud.requestPermissions).not.toHaveBeenCalled();
    expect(tinycloud.ensureEncryptionNetwork).not.toHaveBeenCalled();
    expect(onStatus).not.toHaveBeenCalled();
  });

  it("says what is happening, asks once for network creation, then creates the network", async () => {
    const tinycloud = client({ exists: false });
    const onStatus = vi.fn();
    const setup = createNetworkSetup(tinycloud as never, { address: ADDRESS }, onStatus);
    await setup.ensure();
    expect(onStatus).toHaveBeenCalledExactlyOnceWith(NETWORK_SETUP);
    expect(tinycloud.requestPermissions).toHaveBeenCalledTimes(1);
    expect(tinycloud.requestPermissions).toHaveBeenCalledWith([{ service: "tinycloud.encryption", path: NETWORK_ID, actions: ["network.create"], skipPrefix: true }], { expiryMs: 600_000 });
    expect(tinycloud.ensureEncryptionNetwork).toHaveBeenCalledExactlyOnceWith(NETWORK_ID);
    expect(tinycloud.calls.order).toEqual(["get", "request", "ensure"]);
  });

  it("creates nothing and fails as a sign-in that did not complete when the request is declined", async () => {
    const tinycloud = client({ exists: false, approve: false });
    const setup = createNetworkSetup(tinycloud as never, { address: ADDRESS });
    const failure = await setup.ensure().then(() => undefined, (error: unknown) => error);
    expect(failure).toBeInstanceOf(NetworkSetupDeclinedError);
    expect(senderFailureMessage(failure)).toBe(SENDER_FAILURE.signIn);
    expect(tinycloud.ensureEncryptionNetwork).not.toHaveBeenCalled();
  });

  it("asks again after a decline, because nothing was set up", async () => {
    const tinycloud = client({ exists: false, approve: false });
    const setup = createNetworkSetup(tinycloud as never, { address: ADDRESS });
    await expect(setup.ensure()).rejects.toBeInstanceOf(NetworkSetupDeclinedError);
    tinycloud.requestPermissions.mockResolvedValueOnce({ approved: true });
    await setup.ensure();
    expect(tinycloud.requestPermissions).toHaveBeenCalledTimes(2);
    expect(tinycloud.ensureEncryptionNetwork).toHaveBeenCalledTimes(1);
  });

  it("runs once per session, also when asked together", async () => {
    const tinycloud = client({ exists: false });
    const setup = createNetworkSetup(tinycloud as never, { address: ADDRESS });
    await Promise.all([setup.ensure(), setup.ensure()]);
    await setup.ensure();
    await setup.ensure();
    expect(tinycloud.getEncryptionNetwork).toHaveBeenCalledTimes(1);
    expect(tinycloud.requestPermissions).toHaveBeenCalledTimes(1);
    expect(tinycloud.ensureEncryptionNetwork).toHaveBeenCalledTimes(1);
  });

  it("does not remember a lookup that failed", async () => {
    const tinycloud = client({ exists: true });
    tinycloud.getEncryptionNetwork.mockRejectedValueOnce(new Error("offline"));
    const setup = createNetworkSetup(tinycloud as never, { address: ADDRESS });
    await expect(setup.ensure()).rejects.toThrow("offline");
    await setup.ensure();
    expect(tinycloud.getEncryptionNetwork).toHaveBeenCalledTimes(2);
  });
});
