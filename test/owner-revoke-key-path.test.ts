// A path-bound share's policy root carries decrypt on its own key (`<network>/share/<shareId>`) instead of the bare network. The wallet may still
// be asked to revoke it, and only it: another share's key, a deeper path, another account's network, or a key of the wrong family are not this share's own.
import { getAddress } from "viem";
import { describe, expect, it } from "vitest";
import type { SenderShareRecord } from "@tinycloud/share-sdk";
import { verifyShareRootOnNode } from "../src/share/owner-revoke.js";
import { ownerEncryptionNetwork, type ShareTinyCloud } from "../src/share/openkey-session.js";

const ADDRESS = "0x2f9fad83dbbb1e6bf56acb7e651225c070b7774b";
const OTHER_ADDRESS = "0x1111111111111111111111111111111111111111";
const SPACE = `tinycloud:pkh:eip155:1:${ADDRESS}:applications`;
const NODE = { origin: "https://node.example.invalid", nodeDid: "did:key:z6MkqGC3nWZhYieEVTVDKW5v588CiGfsDSmRVG9ZwwWTvLSK" };
const K1 = "did:key:z6MktULudTtAsAhRegYPiZ6631RV3viv12qd4GQF8z1xB22S";
const SHARE_ID = "5b0e2a4c-0000-4000-8000-000000000001";
const PATH = `xyz.tinycloud.share/shares/${SHARE_ID}/qa.txt`;
const checksummed = (address: string): string => `urn:tinycloud:encryption:did:pkh:eip155:1:${getAddress(address)}:default`;

const record = {
  shareId: SHARE_ID, ownerDid: K1, ownerDelegationCid: "policy-root",
  target: { origin: NODE.origin, nodeAudience: NODE.nodeDid, spaceId: SPACE },
  resource: { kind: "exact", path: PATH },
} as unknown as SenderShareRecord;

const kv = { resource: `${SPACE}/kv/${PATH}`, actions: ["tinycloud.kv/get", "tinycloud.kv/metadata"], caveats: [] };

async function verify(encryption: string): Promise<"active" | "revoked"> {
  const row = { cid: "policy-root", direction: "granted", delegatorDid: K1, delegateDid: "did:key:z6MkEnforcer", resources: [kv, { resource: encryption, actions: ["tinycloud.encryption/decrypt"], caveats: [] }], parents: [], status: "active" };
  const tinycloud = { delegations: { query: async () => ({ ok: true, data: { items: [row], nextCursor: undefined } }) } } as unknown as ShareTinyCloud;
  return verifyShareRootOnNode({ tinycloud, address: ADDRESS, node: NODE, record, cid: "policy-root", kind: "policy-root" });
}

describe("the node check on a share's policy root", () => {
  it.each([
    ["its own key, checksummed as the node lists it", `${checksummed(ADDRESS)}/share/${SHARE_ID}`],
    ["its own key, lower-cased", `${ownerEncryptionNetwork(ADDRESS)}/share/${SHARE_ID}`],
    ["the bare network (a share made before the key path)", ownerEncryptionNetwork(ADDRESS)],
  ])("accepts a root that grants %s", async (_name, encryption) => {
    await expect(verify(encryption)).resolves.toBe("active");
  });

  it.each([
    ["another share's key", `${checksummed(ADDRESS)}/share/another-share-0123456789`],
    ["a path below the share's key", `${checksummed(ADDRESS)}/share/${SHARE_ID}/more`],
    ["a key of another family", `${checksummed(ADDRESS)}/keys/${SHARE_ID}`],
    ["another account's key for this share id", `${checksummed(OTHER_ADDRESS)}/share/${SHARE_ID}`],
    ["another account's network", ownerEncryptionNetwork(OTHER_ADDRESS)],
  ])("refuses a root that also grants %s", async (_name, encryption) => {
    await expect(verify(encryption)).rejects.toThrow("revoke-earlier-sign-in");
  });
});
