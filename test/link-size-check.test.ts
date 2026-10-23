// @vitest-environment node
import { describe, expect, it } from "vitest";
import { signCompactUcanRootAuthorization } from "@tinycloud/sdk-core";
import { toBase64Url, fromBase64Url } from "@tinycloud/share-envelope";
import { prepareAddressedShare, publishAddressedShare, type AddressedPolicyRegistrationReceipt, type AddressedSharePublishOptions } from "@tinycloud/share-sdk";
import { assertShareFitsLink, sealedBytesUpperBound, type SealingAuthority, type ShareSizeInput } from "../src/share/link-size.js";
import { ShareTooLargeForLink } from "../src/short-links/errors.js";
import { LINK_BODY_MAX_BYTES } from "../src/short-links/limits.js";
import { ISSUER_DID, signWithIssuer } from "./fixtures/link-material.js";

const NODE_DID = "did:key:z6MkqGC3nWZhYieEVTVDKW5v588CiGfsDSmRVG9ZwwWTvLSK";
const NETWORK = "urn:tinycloud:encryption:did:pkh:eip155:1:0x1234567890abcdef1234567890abcdef12345678:default";
const SPACE = "tinycloud:pkh:eip155:1:0x1234567890abcdef1234567890abcdef12345678:applications";

/** Local signing only, like the owner's session. Counts what it is asked to do. */
function authority(): SealingAuthority & { readonly roots: { count: number } } {
  const roots = { count: 0 };
  return {
    roots,
    ownerDid: ISSUER_DID,
    sign: signWithIssuer,
    createOwnerRoot: async (input) => {
      roots.count += 1;
      const kv = input.capabilities.find((capability) => capability.kind === "kv")!;
      const root = await signCompactUcanRootAuthorization({
        issuerDid: ISSUER_DID, audienceDid: input.audienceDid,
        attenuation: { [kv.resource]: { "tinycloud.kv/get": [{ type: "xyz.tinycloud.resource/selector", kind: kv.selector, value: kv.resource }] } },
        facts: [{ role: input.role, policyId: input.policyId, policyCid: input.policyCid, ownerDid: ISSUER_DID, nodeAudience: input.nodeAudience }],
        notBefore: Math.floor(input.notBefore.getTime() / 1000), expiresAt: Math.floor(input.expiresAt.getTime() / 1000),
        nonce: toBase64Url(crypto.getRandomValues(new Uint8Array(16))), sign: signWithIssuer,
      });
      return { cid: root.cid, delegationHeader: { Authorization: root.authorization }, delegateDID: input.audienceDid, spaceId: SPACE, path: "", actions: [], expiry: input.expiresAt };
    },
  };
}

function input(path: string, filename = "report.md"): ShareSizeInput {
  const request = { target: { kind: "email" as const, address: "reader@example.com" }, actions: ["read" as const], policyActions: ["tinycloud.kv/get" as const, "tinycloud.kv/metadata" as const], filename };
  const { credentialRequirement } = prepareAddressedShare(request);
  return {
    shareId: "abcdefghijklmnopqrstuvwxyz234567", shareOrigin: "https://share.tinycloud.xyz", nodeOrigin: "https://node.example", nodeAudience: NODE_DID, enforcerDid: NODE_DID, spaceId: SPACE,
    ...request, resource: { kind: "exact", path }, ...(credentialRequirement === undefined ? {} : { credentialRequirement }),
    mediaType: "text/markdown", byteLength: 1234, expiresAt: new Date(Date.now() + 7 * 86_400_000),
    encryptionNetwork: NETWORK,
  };
}

/** What the real publish seals: the receipt values a node and an upload return, at ordinary lengths. */
async function realSealedBytes(base: ShareSizeInput): Promise<number> {
  let size = 0;
  const own = authority();
  const { encryptionNetwork, ...rest } = base;
  await publishAddressedShare({
    ...rest,
    contentSource: { shareId: base.shareId, kvResource: `${base.spaceId}/kv/${base.resource.path}`, selector: base.resource.kind, encryptionNetwork, mode: "immutable", encryptedSymmetricKeyDigestHex: "a".repeat(64), keyVersion: 1, initialCiphertextDigestHex: "b".repeat(64) },
    onDeliveryMaterial: (material) => { size = fromBase64Url(material.sealedEnvelope).byteLength; },
    authority: {
      ...own,
      registerPolicy: async (registration): Promise<AddressedPolicyRegistrationReceipt> => ({
        policyCid: registration.policyCid, policyRootCid: registration.policyRoot.cid, enforcementRootCid: registration.enforcementRoot.cid,
        attestedEnforcerBinding: {
          schema: "xyz.tinycloud.policy/attested-enforcer/v2", enforcerDid: NODE_DID, nodeAudience: NODE_DID, attestationBindingDigestHex: "c".repeat(64),
          issuedAt: "2026-10-24T12:00:00Z", expiresAt: new Date(Date.now() + 8 * 86_400_000).toISOString(), signature: { suite: "Ed25519", signerDid: NODE_DID, value: toBase64Url(new Uint8Array(64).fill(7)) },
        },
      }),
    },
  });
  return size;
}

describe("the size check before any write", () => {
  it("passes an ordinary share and asks only for local signing", async () => {
    const own = authority();
    await expect(assertShareFitsLink(input("xyz.tinycloud.share/shares/abcdefghijklmnopqrstuvwxyz234567/report.md"), own)).resolves.toBeUndefined();
    expect(own.roots.count).toBe(2);
  });

  it("refuses a share whose path makes the sealed body over the limit", async () => {
    const longPath = `xyz.tinycloud.share/shares/abcdefghijklmnopqrstuvwxyz234567/${Array.from({ length: 330 }, () => "d".repeat(60)).join("/")}/report.md`;
    await expect(assertShareFitsLink(input(longPath), authority())).rejects.toBeInstanceOf(ShareTooLargeForLink);
  });

  it("measures at least what the real publish seals, and not much more", async () => {
    for (const path of [
      "xyz.tinycloud.share/shares/abcdefghijklmnopqrstuvwxyz234567/report.md",
      `xyz.tinycloud.share/shares/abcdefghijklmnopqrstuvwxyz234567/${"d".repeat(60)}/${"e".repeat(60)}/report.md`,
    ]) {
      const base = input(path);
      const real = await realSealedBytes(base);
      const measured = await sealedBytesUpperBound(base, authority());
      expect(real).toBeGreaterThan(0);
      expect(measured).toBeGreaterThanOrEqual(real);
      expect(measured - real).toBeLessThan(400);
      expect(measured).toBeLessThan(LINK_BODY_MAX_BYTES);
    }
  });
});
