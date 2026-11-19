import { describe, expect, it } from "vitest";
import { TinyCloudNode } from "@tinycloud/node-sdk";
import type { PermissionEntry, TinyCloudSession } from "@tinycloud/sdk-core";
import { SiweMessage } from "siwe";

const ADDRESS = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";

function restoredSession(): TinyCloudSession {
  const issuedAt = new Date(Date.now() - 60_000).toISOString();
  const expiry = new Date(Date.now() + 10 * 60_000).toISOString();
  return {
    address: ADDRESS,
    chainId: 1,
    sessionKey: "0xsession-key",
    siwe: new SiweMessage({ domain: "node.example", address: ADDRESS, uri: "https://node.example", version: "1", chainId: 1, nonce: "abc12345", issuedAt, expirationTime: expiry }).prepareMessage(),
    signature: "0xsignature",
    jwk: {},
    delegationHeader: { Authorization: "Bearer test" },
    spaceId: "applications",
    delegationCid: "bafy-test-session",
    verificationMethod: "did:key:z6Mk-test#z6Mk-test",
  };
}

const uncovered: PermissionEntry = {
  service: "tinycloud.kv",
  space: "applications",
  path: "xyz.example.restore-boundary/settings/",
  actions: ["put"],
  skipPrefix: true,
};

describe("runtime permission escalation signer prerequisite", () => {
  it("requires a wallet signer for an uncovered grant on a restored session", async () => {
    const node = new TinyCloudNode({ host: "https://node.example" });
    Object.defineProperty(node, "_restoredTcSession", { value: restoredSession(), configurable: true });

    await expect(node.grantRuntimePermissions([uncovered]))
      .rejects.toThrow("grantRuntimePermissions requires wallet mode with a signer or privateKey.");
  });
});
