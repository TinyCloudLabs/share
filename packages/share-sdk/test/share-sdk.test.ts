import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import { blake3 } from "@noble/hashes/blake3";
import { keccak_256 } from "@noble/hashes/sha3";
import { ed25519 } from "@noble/curves/ed25519";
import { secp256k1 } from "@noble/curves/secp256k1";
import { canonicalize, didKeyFromEd25519PublicKey, fromBase64Url, toBase64Url } from "@tinycloud/share-envelope";
import {
  accessSharedContent,
  createShareLink,
  sendShareEmail,
  type ContentAccessDependencies,
  type ShareArtifact,
  type ShareLinkPolicy,
  type ShareTransport,
} from "../src/index.js";
import { SIGNATURE_DOMAINS, type SenderScope } from "../../../src/email-share/protocol.js";

const vectors = JSON.parse(readFileSync(new URL("../../../test/vectors/email-claim-v1/positive.json", import.meta.url), "utf8")) as { readonly scenarios: readonly [Record<string, any>, ...Record<string, any>[]] };
const fixture = vectors.scenarios[0];
const senderSeed = new Uint8Array(32).fill(0x44);
const nodeSeed = new Uint8Array(32).fill(0x42);
const senderPublicKey = ed25519.getPublicKey(senderSeed);
const senderDid = didKeyFromEd25519PublicKey(senderPublicKey);
const source = fixture.source;

function nodeCid(bytes: Uint8Array): string {
  const alphabet = "abcdefghijklmnopqrstuvwxyz234567";
  const data = Uint8Array.of(1, 0x55, 0x1e, 0x20, ...blake3(bytes));
  let buffer = 0; let bits = 0; let result = "b";
  for (const byte of data) { buffer = (buffer << 8) | byte; bits += 8; while (bits >= 5) { bits -= 5; result += alphabet[(buffer >>> bits) & 31]; } }
  if (bits !== 0) result += alphabet[(buffer << (5 - bits)) & 31];
  return result;
}

const ownerPrivateKey = new Uint8Array(32).fill(1);
const ownerPublicKey = secp256k1.getPublicKey(ownerPrivateKey, false);
const policyOwnerDid = `did:pkh:eip155:1:0x${Array.from(keccak_256(ownerPublicKey.slice(1)).slice(-20), (byte) => byte.toString(16).padStart(2, "0")).join("")}`;

function standardMaterial(): { readonly material: Record<string, any>; readonly digest: string } {
  const material = JSON.parse(JSON.stringify(fixture.authorityMaterial)) as Record<string, any>;
  for (const key of ["policyAuthorityBytes", "policyEnforcementBytes"] as const) {
    const parent = JSON.parse(new TextDecoder().decode(fromBase64Url(String(material[key]))) ) as Record<string, any>;
    const facts = parent.facts as Record<string, unknown>;
    facts["xyz.tinycloud.policy/ownerDid"] = policyOwnerDid;
    parent.issuerDid = policyOwnerDid;
    delete parent.signature;
    delete parent.delegationCid;
    const unsigned = new TextEncoder().encode(canonicalize(parent));
    const digest = new Uint8Array(createHash("sha256").update(new TextEncoder().encode("xyz.tinycloud.policy/enforcement-delegation/v1\0")).update(unsigned).digest());
    const signature = secp256k1.sign(keccak_256(new Uint8Array([...new TextEncoder().encode("\x19Ethereum Signed Message:\n32"), ...digest])), ownerPrivateKey, { lowS: true });
    const signed = { ...parent, signature: { suite: "eip191-secp256k1-sha256-jcs-v1", value: toBase64Url(new Uint8Array([...signature.toBytes("compact"), signature.recovery])) } };
    const parentCid = nodeCid(new TextEncoder().encode(canonicalize(signed)));
    material[key] = toBase64Url(new TextEncoder().encode(canonicalize({ ...signed, delegationCid: parentCid })));
    material[key.replace("Bytes", "Cid")] = parentCid;
  }
  material.policyOwnerDid = policyOwnerDid;
  material.relationship = { policyOwnerDid, senderDid, authenticated: true };
  const mapping = material.mapping as Record<string, unknown>;
  mapping.policyAuthorityCid = material.policyAuthorityCid;
  mapping.policyEnforcementCid = material.policyEnforcementCid;
  for (const status of material.statusObservations as Array<Record<string, any>>) {
    status.parentCid = status.parentCid === fixture.authorityMaterial.policyAuthorityCid ? material.policyAuthorityCid : material.policyEnforcementCid;
    status.checkedAt = "2026-07-20T11:59:00.000Z";
    status.freshUntil = "2026-07-20T12:04:00.000Z";
    status.signerKid = `${didKeyFromEd25519PublicKey(ed25519.getPublicKey(nodeSeed))}#${didKeyFromEd25519PublicKey(ed25519.getPublicKey(nodeSeed)).slice("did:key:".length)}`;
    const unsigned = { ...status }; delete unsigned.signature;
    status.signature = { alg: "EdDSA", kid: status.signerKid, value: toBase64Url(ed25519.sign(new TextEncoder().encode(`xyz.tinycloud.share/authority-status/v1\0${canonicalize(unsigned)}`), nodeSeed)) };
  }
  const attestation = material.attestation as Record<string, any>;
  attestation.expiresAt = "2026-07-23T12:04:00.000Z";
  const unsignedAttestation = { ...attestation }; delete unsignedAttestation.signature;
  attestation.signature = { alg: "EdDSA", kid: String(attestation.localSignerKid), value: toBase64Url(ed25519.sign(new TextEncoder().encode(`xyz.tinycloud.share/enrollment-attestation/v1\0${canonicalize(unsignedAttestation)}`), nodeSeed)) };
  return { material, digest: createHash("sha256").update(canonicalize(material)).digest("base64url") };
}

const authority = standardMaterial();

const scope: SenderScope = {
  policyOwnerDid,
  senderDid,
  signingCapability: { capabilityId: "A".repeat(22), publicKey: senderPublicKey },
  signer: {
    publicKey: senderPublicKey,
    sign: async ({ purpose, message }) => ed25519.sign(new TextEncoder().encode(`${purpose === "envelope" ? SIGNATURE_DOMAINS.envelope : SIGNATURE_DOMAINS.inviteAuthorization}${message}`), senderSeed),
  },
  shareOrigin: "https://share.tinycloud.xyz",
  delegation: "uCAESA.kv.terminal",
  delegationCid: fixture.delegationCid,
  authorityMaterialHandle: "amh_kv_001",
  authorityMaterialDigest: authority.digest,
  targetOrigin: fixture.enrollment.targetOrigin,
  nodeAudience: fixture.enrollment.nodeAudience,
  spaceId: source.space,
  documentName: "Project plan.md",
  senderTrust: "verified",
  trustedNode: { ...fixture.enrollment, invitationPublicKey: fromBase64Url(fixture.enrollment.invitationPublicKey) },
  authorityMaterial: authority.material,
};

const policy: ShareLinkPolicy = {
  recipientEmail: fixture.policy.recipientEmail,
  source,
  action: source.action,
  resource: source.path,
  expiresAt: "2026-07-23T12:00:00.000Z",
  target: { origin: scope.targetOrigin, nodeAudience: scope.nodeAudience, spaceId: scope.spaceId },
  policyCid: fixture.policyCid,
  policyDigest: createHash("sha256").update(fromBase64Url(fixture.policyBytes)).digest("base64url"),
  contentSourceDigest: fixture.policy.contentSourceDigest,
  delegationCid: scope.delegationCid,
  authorityMaterialDigest: scope.authorityMaterialDigest,
  policyBytes: fixture.policyBytes,
  policyAuthorityCid: authority.material.policyAuthorityCid,
  policyAuthorityBytes: authority.material.policyAuthorityBytes,
  policyEnforcementCid: authority.material.policyEnforcementCid,
  policyEnforcementBytes: authority.material.policyEnforcementBytes,
};

function deliveryTransport(authorizeInvitation: ShareTransport["authorizeInvitation"]): ShareTransport {
  return {
    authorizeInvitation,
    requestDelivery: vi.fn(async () => ({ status: "accepted" as const, retryAfterSeconds: 20, delegationCid: scope.delegationCid, authorityMaterialHandle: scope.authorityMaterialHandle, authorityMaterialDigest: scope.authorityMaterialDigest })),
    resend: vi.fn(),
    activate: vi.fn(),
    claimChallenge: vi.fn(),
    claimRedeem: vi.fn(),
    policyChallenge: vi.fn(),
    policySession: vi.fn(),
    read: vi.fn(),
  };
}

async function generatedShare(): Promise<{ share: ShareArtifact; uploads: number; deliveries: ReturnType<typeof vi.fn> }> {
  let uploads = 0;
  const share = await createShareLink({
    email: "Alice+Notes@EXAMPLE.COM",
    source,
    scope,
    shareId: "share-sdk-test",
    expiresAt: "2026-07-23T12:00:00.000Z",
    now: "2026-07-20T12:00:00.000Z",
    policy,
    adapters: { uploadEnvelope: async () => { uploads += 1; } },
  });
  const deliveries = vi.fn();
  return { share, uploads, deliveries };
}

describe("@tinycloud/share-sdk", () => {
  it("keeps link generation independent from email delivery", async () => {
    const result = await generatedShare();
    expect(result.uploads).toBe(1);
    expect(result.share.shareUrl).toMatch(/^https:\/\/share\.tinycloud\.xyz\/s\/b[a-z2-7]+#k=[A-Za-z0-9_-]{43}$/);
    expect(result.share.action).toBe(source.action);
    expect(result.share.recipientEmail).toBe("Alice+Notes@example.com");
  });

  it("delivers the exact pre-generated link once after signed Node authorization", async () => {
    const { share } = await generatedShare();
    let deliveredUrl: string | undefined;
    const authorizeInvitation = vi.fn(async (input: Record<string, unknown>) => {
      const request = input.request as Record<string, unknown>;
      const authorization = {
        type: "TinyCloudShareInviteAuthorization", version: 1, jti: request.jti, senderDid: request.senderDid, shareCid: request.shareCid, shareId: request.shareId, policyCid: request.policyCid, delegationCid: request.delegationCid, authorityMaterialHandle: request.authorityMaterialHandle, authorityMaterialDigest: request.authorityMaterialDigest, recipientEmail: request.recipientEmail, targetOrigin: request.targetOrigin, nodeAudience: request.nodeAudience, returnOrigin: scope.shareOrigin, documentName: request.documentName, senderTrust: request.senderTrust, contentSource: request.contentSource, contentSourceDigest: request.contentSourceDigest, shareExpiresAt: request.shareExpiresAt, issuedAt: "2026-07-20T12:00:00.000Z", expiresAt: "2026-07-20T12:05:00.000Z", reportAbuseToken: request.reportAbuseToken,
      };
      return { authorization: authorization as never, proof: { alg: "EdDSA" as const, kid: scope.trustedNode.invitationKid, signature: toBase64Url(ed25519.sign(new TextEncoder().encode(`${SIGNATURE_DOMAINS.inviteAuthorization}${canonicalize(authorization)}`), nodeSeed)) } };
    });
    const transport = deliveryTransport(authorizeInvitation);
    const originalDelivery = transport.requestDelivery;
    transport.requestDelivery = vi.fn(async (input) => { deliveredUrl = String(input.shareUrl); return originalDelivery(input); });
    const receipt = await sendShareEmail({ share, scope, adapters: transport });
    expect(receipt).toMatchObject({ status: "accepted", state: "queued", shareCid: share.shareCid, shareId: share.shareId });
    expect(deliveredUrl).toBe(share.shareUrl);
    expect(authorizeInvitation).toHaveBeenCalledTimes(1);
    expect(transport.requestDelivery).toHaveBeenCalledTimes(1);
  });

  it("rejects authorization substitution before delivery", async () => {
    const { share } = await generatedShare();
    const authorizeInvitation = vi.fn(async (input: Record<string, unknown>) => {
      const request = input.request as Record<string, unknown>;
      const authorization = { ...request, type: "TinyCloudShareInviteAuthorization", version: 1, recipientEmail: "wrong@example.com", returnOrigin: scope.shareOrigin, issuedAt: "2026-07-20T12:00:00.000Z", expiresAt: "2026-07-20T12:05:00.000Z" };
      return { authorization: authorization as never, proof: { alg: "EdDSA" as const, kid: scope.trustedNode.invitationKid, signature: toBase64Url(ed25519.sign(new TextEncoder().encode(`${SIGNATURE_DOMAINS.inviteAuthorization}${canonicalize(authorization)}`), nodeSeed)) } };
    });
    const transport = deliveryTransport(authorizeInvitation);
    await expect(sendShareEmail({ share, scope, adapters: transport })).rejects.toThrow(/invitation-authorization-mismatch/);
    expect(transport.requestDelivery).not.toHaveBeenCalled();
  });

  it("runs content access independently with synchronous scrub and injected protocol seams", async () => {
    const { share } = await generatedShare();
    const events: string[] = [];
    const fakeController = {
      state: { state: "claimed", claim: { holder: { did: "did:key:z6MkhHolder", privateKey: {} as CryptoKey }, credential: "credential", expiresAt: "2026-07-23T12:00:00.000Z", persisted: false } } as const,
      subscribe: () => () => undefined,
      openDocument: async () => { events.push("claim"); },
      read: async () => "# Project plan\n",
      retry: async () => undefined,
      useOtp: () => undefined,
      submitOtp: async () => undefined,
      resend: async () => undefined,
      forget: () => undefined,
    };
    const dependencies: ContentAccessDependencies = {
      registryBaseUrl: "https://registry.tinycloud.xyz",
      transport: {} as ShareTransport,
      credentialTrust: {} as never,
      scrub: () => events.push("scrub"),
      resolve: async () => ({ state: "policy-email-claim-required", envelope: {} as never, shareCid: share.shareCid, policy: { type: "TinyCloudSharePolicy" } }),
      verifyShare: async () => { events.push("verify"); return { shareId: share.shareId, shareCid: share.shareCid, policyCid: share.policyCid, recipientEmail: share.recipientEmail, recipientHint: "A***@example.com", expiry: share.expiresAt, nodeOrigin: scope.targetOrigin, nodeAudience: scope.nodeAudience, requestOrigin: scope.shareOrigin, delegationCid: scope.delegationCid, authorityMaterialHandle: scope.authorityMaterialHandle, authorityMaterialDigest: scope.authorityMaterialDigest, contentSource: source, contentSourceDigest: "A".repeat(43), action: source.action, resource: source.path, trustedNode: scope.trustedNode }; },
      createController: () => fakeController,
    };
    const result = await accessSharedContent({ shareUrl: `${share.shareUrl}&i=${"B".repeat(22)}&c=${"C".repeat(43)}`, confirmAccess: () => { events.push("confirm"); return true; }, dependencies });
    expect(result.content).toBe("# Project plan\n");
    expect(events).toEqual(["scrub", "verify", "confirm", "claim"]);
  });
});
