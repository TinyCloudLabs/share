import { describe, expect, it, vi } from "vitest";
import { defaultEncryptionNetworkForOwner } from "@tinycloud/share-sdk";
import { createNetworkSetup } from "../src/share/network-setup.js";

const ADDRESS = "0x1234567890abcdef1234567890abcdef12345678";
const NETWORK = defaultEncryptionNetworkForOwner({ address: ADDRESS });

describe("the one-time setup's approval", () => {
  it("asks for network.create for ten minutes, not the SDK's 30-day default", async () => {
    const requestPermissions = vi.fn(async () => ({ approved: true }));
    const tinycloud = { getEncryptionNetwork: vi.fn(async () => null), ensureEncryptionNetwork: vi.fn(async () => ({ id: NETWORK })), requestPermissions, hasPermissions: vi.fn(() => false) };
    await createNetworkSetup(tinycloud as never, { address: ADDRESS }).ensure();
    expect(requestPermissions).toHaveBeenCalledTimes(1);
    expect(requestPermissions).toHaveBeenCalledWith([{ service: "tinycloud.encryption", path: NETWORK, actions: ["network.create"], skipPrefix: true }], { expiryMs: 600_000 });
  });
});
