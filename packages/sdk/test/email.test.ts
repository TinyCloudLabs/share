import {readFileSync} from "node:fs";
import {createHash} from "node:crypto";
import {blake3} from "@noble/hashes/blake3";
import {keccak_256} from "@noble/hashes/sha3";
import {ed25519} from "@noble/curves/ed25519";
import {secp256k1} from "@noble/curves/secp256k1";
import {describe, expect, it, vi} from "vitest";
import {
  canonicalize,
  didKeyFromEd25519PublicKey,
  toBase64Url,
  fromBase64Url,
} from "@tinycloud/share-envelope";
import {
  createShareLink,
  type ShareArtifact,
  type ShareLinkPolicy,
} from "../../share-sdk/src/index.js";
import {SIGNATURE_DOMAINS, type SenderScope} from "../../../src/email-share/protocol.js";
import {
  sendShareEmail,
  type ShareEmailAdapter,
} from "../src/email.js";

const senderSeed = new Uint8Array(32).fill(0x44);
const nodeSeed = new Uint8Array(32).fill(0x42);
const senderPublicKey = ed25519.getPublicKey(senderSeed);
const senderDid = didKeyFromEd25519PublicKey(senderPublicKey);
const vectors = JSON.parse(readFileSync(new URL("../../../test/vectors/email-claim-v1/positive.json", import.meta.url), "utf8")) as {readonly scenarios: readonly [Record<string, any>, ...Record<string, any>[]]};
const fixture = vectors.scenarios[0];
const source = {
  kind: "kv" as const,
  space: "did:pkh:eip155:1:0x1111111111111111111111111111111111111111",
  path: "documents/plan.md",
  action: "tinycloud.kv/get" as const,
};

const ownerPrivateKey = new Uint8Array(32).fill(1);
const ownerPublicKey = secp256k1.getPublicKey(ownerPrivateKey, false);
const policyOwnerDid = `did:pkh:eip155:1:0x${Array.from(keccak_256(ownerPublicKey.slice(1)).slice(-20), (byte) => byte.toString(16).padStart(2, "0")).join("")}`;

function nodeCid(bytes: Uint8Array): string {
  const alphabet = "abcdefghijklmnopqrstuvwxyz234567";
  const data = Uint8Array.of(1, 0x55, 0x1e, 0x20, ...blake3(bytes));
  let buffer = 0; let bits = 0; let result = "b";
  for (const byte of data) { buffer = (buffer << 8) | byte; bits += 8; while (bits >= 5) { bits -= 5; result += alphabet[(buffer >>> bits) & 31]; } }
  if (bits !== 0) result += alphabet[(buffer << (5 - bits)) & 31];
  return result;
}

function standardMaterial(): {readonly material: Record<string, any>; readonly digest: string} {
  const material = JSON.parse(JSON.stringify(fixture.authorityMaterial)) as Record<string, any>;
  for (const key of ["policyAuthorityBytes", "policyEnforcementBytes"] as const) {
    const parent = JSON.parse(new TextDecoder().decode(fromBase64Url(String(material[key])))) as Record<string, any>;
    const facts = parent.facts as Record<string, unknown>;
    facts["xyz.tinycloud.policy/ownerDid"] = policyOwnerDid;
    parent.issuerDid = policyOwnerDid;
    delete parent.signature; delete parent.delegationCid;
    const unsigned = new TextEncoder().encode(canonicalize(parent));
    const digest = new Uint8Array(createHash("sha256").update(new TextEncoder().encode("xyz.tinycloud.policy/enforcement-delegation/v1\0")).update(unsigned).digest());
    const signature = secp256k1.sign(keccak_256(new Uint8Array([...new TextEncoder().encode("\x19Ethereum Signed Message:\n32"), ...digest])), ownerPrivateKey, {lowS: true});
    const signed = {...parent, signature: {suite: "eip191-secp256k1-sha256-jcs-v1", value: toBase64Url(new Uint8Array([...signature.toBytes("compact"), signature.recovery]))}};
    const parentCid = nodeCid(new TextEncoder().encode(canonicalize(signed)));
    material[key] = toBase64Url(new TextEncoder().encode(canonicalize({...signed, delegationCid: parentCid})));
    material[key.replace("Bytes", "Cid")] = parentCid;
  }
  material.policyOwnerDid = policyOwnerDid;
  material.senderDid = senderDid;
  material.relationship = {policyOwnerDid, senderDid, authenticated: true};
  const mapping = material.mapping as Record<string, unknown>;
  mapping.policyAuthorityCid = material.policyAuthorityCid; mapping.policyEnforcementCid = material.policyEnforcementCid;
  for (const status of material.statusObservations as Array<Record<string, any>>) {
    status.parentCid = status.parentCid === fixture.authorityMaterial.policyAuthorityCid ? material.policyAuthorityCid : material.policyEnforcementCid;
    status.checkedAt = "2026-07-20T11:59:00.000Z"; status.freshUntil = "2026-07-20T12:04:00.000Z";
    status.signerKid = `${didKeyFromEd25519PublicKey(ed25519.getPublicKey(nodeSeed))}#${didKeyFromEd25519PublicKey(ed25519.getPublicKey(nodeSeed)).slice("did:key:".length)}`;
    const unsigned = {...status}; delete unsigned.signature;
    status.signature = {alg: "EdDSA", kid: status.signerKid, value: toBase64Url(ed25519.sign(new TextEncoder().encode(`xyz.tinycloud.share/authority-status/v1\0${canonicalize(unsigned)}`), nodeSeed))};
  }
  const attestation = material.attestation as Record<string, any>;
  attestation.expiresAt = "2026-07-23T12:04:00.000Z";
  const unsignedAttestation = {...attestation}; delete unsignedAttestation.signature;
  attestation.signature = {alg: "EdDSA", kid: String(attestation.localSignerKid), value: toBase64Url(ed25519.sign(new TextEncoder().encode(`xyz.tinycloud.share/enrollment-attestation/v1\0${canonicalize(unsignedAttestation)}`), nodeSeed))};
  return {material, digest: createHash("sha256").update(canonicalize(material)).digest("base64url")};
}

const authority = standardMaterial();

const scope: SenderScope = {
  policyOwnerDid,
  senderDid,
  signingCapability: {capabilityId: "A".repeat(22), publicKey: senderPublicKey},
  signer: {
    publicKey: senderPublicKey,
    sign: async ({purpose, message}) => ed25519.sign(
      new TextEncoder().encode(`${purpose === "envelope" ? SIGNATURE_DOMAINS.envelope : SIGNATURE_DOMAINS.inviteAuthorization}${message}`),
      senderSeed,
    ),
  },
  shareOrigin: "https://share.tinycloud.xyz",
  delegation: "uCAESA.kv.terminal",
  delegationCid: fixture.delegationCid,
  authorityMaterialHandle: "amh_kv_001",
  authorityMaterialDigest: authority.digest,
  targetOrigin: "https://node.example",
  nodeAudience: "did:web:node.example",
  spaceId: source.space,
  documentName: "Project plan.md",
  senderTrust: "verified",
  trustedNode: {
    targetOrigin: "https://node.example",
    nodeAudience: "did:web:node.example",
    invitationKid: "did:web:node.example#invitation-key-1",
    invitationPublicKey: ed25519.getPublicKey(nodeSeed),
    keyVersion: 1,
    enabled: true,
  },
  authorityMaterial: authority.material,
};

const policy: ShareLinkPolicy = {
  recipientEmail: "Alice+Notes@example.com",
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

async function generatedShare(): Promise<ShareArtifact> {
  return createShareLink({
    email: "Alice+Notes@EXAMPLE.COM",
    source,
    scope,
    shareId: "share-sdk-email-test",
    expiresAt: "2026-07-23T12:00:00.000Z",
    now: "2026-07-20T12:00:00.000Z",
    policy,
    adapters: {uploadEnvelope: async () => undefined},
  });
}

function adapterFor(
  modifyAuthorization: (authorization: Record<string, unknown>) => Record<string, unknown> = (authorization) => authorization,
): ShareEmailAdapter & {readonly authorize: ReturnType<typeof vi.fn>; readonly deliver: ReturnType<typeof vi.fn>} {
  const authorize = vi.fn(async (input: Record<string, unknown>) => {
    const request = input.request as Record<string, unknown>;
    const authorization = modifyAuthorization({
      type: "TinyCloudShareInviteAuthorization",
      version: request.version,
      jti: request.jti,
      senderDid: request.senderDid,
      shareCid: request.shareCid,
      shareId: request.shareId,
      policyCid: request.policyCid,
      delegationCid: request.delegationCid,
      authorityMaterialHandle: request.authorityMaterialHandle,
      authorityMaterialDigest: request.authorityMaterialDigest,
      ...(request.version === 2 ? {
        recipientMatcher: request.recipientMatcher,
        deliveryEmail: request.deliveryEmail,
        shareUrl: request.shareUrl,
        actions: request.actions,
        resource: request.resource,
        requestBodyDigest: request.requestBodyDigest,
        idempotencyKey: request.idempotencyKey,
      } : { recipientEmail: request.recipientEmail }),
      targetOrigin: request.targetOrigin,
      nodeAudience: request.nodeAudience,
      returnOrigin: scope.shareOrigin,
      documentName: request.documentName,
      senderTrust: request.senderTrust,
      contentSource: request.contentSource,
      contentSourceDigest: request.contentSourceDigest,
      shareExpiresAt: request.shareExpiresAt,
      issuedAt: "2026-07-20T12:00:00.000Z",
      expiresAt: "2026-07-20T12:05:00.000Z",
      reportAbuseToken: request.reportAbuseToken,
    });
    return {
      authorization: authorization as never,
      proof: {
        alg: "EdDSA" as const,
        kid: scope.trustedNode.invitationKid,
        signature: toBase64Url(ed25519.sign(
          new TextEncoder().encode(`${SIGNATURE_DOMAINS.inviteAuthorization}${canonicalize(authorization)}`),
          nodeSeed,
        )),
      },
    };
  });
  const deliver = vi.fn(async () => ({
    status: "accepted" as const,
    retryAfterSeconds: 20,
    delegationCid: scope.delegationCid,
    authorityMaterialHandle: scope.authorityMaterialHandle,
    authorityMaterialDigest: scope.authorityMaterialDigest,
  }));
  return {
    authorizeInvitation: authorize,
    requestDelivery: deliver,
    authorize,
    deliver,
  } as ShareEmailAdapter & {readonly authorize: typeof authorize; readonly deliver: typeof deliver};
}

describe("email SDK lane", () => {
  it("delivers the identical pre-generated link exactly once after real Node authorization", async () => {
    const share = await generatedShare();
    const adapter = adapterFor();

    await expect(sendShareEmail({share, scope, adapters: adapter})).resolves.toMatchObject({
      status: "accepted",
      state: "queued",
      shareCid: share.shareCid,
      shareId: share.shareId,
      recipientEmail: share.recipientEmail,
    });

    expect(adapter.authorize).toHaveBeenCalledTimes(1);
    expect(adapter.deliver).toHaveBeenCalledTimes(1);
    const delivery = adapter.deliver.mock.calls[0]?.[0] as Record<string, unknown>;
    expect(delivery.shareUrl).toBe(share.shareUrl);
    expect(delivery.authorization).toMatchObject({
      deliveryEmail: share.recipientEmail,
      policyCid: share.policyCid,
      contentSource: source,
      targetOrigin: scope.targetOrigin,
      nodeAudience: scope.nodeAudience,
      shareExpiresAt: share.expiresAt,
    });
  });

  it.each([
    ["recipient", {deliveryEmail: "other@example.com"}],
    ["policy", {policyCid: "bafkreiaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}],
    ["resource", {contentSource: {...source, path: "documents/other.md"}}],
    ["action", {contentSource: {...source, action: "tinycloud.sql/read"}}],
    ["expiry", {shareExpiresAt: "2026-07-24T12:00:00.000Z"}],
    ["target", {targetOrigin: "https://other.example"}],
  ] as const)("denies Node authorization %s substitution before delivery", async (_name, change) => {
    const share = await generatedShare();
    const adapter = adapterFor((authorization) => ({...authorization, ...change}));

    await expect(sendShareEmail({share, scope, adapters: adapter})).rejects.toThrow(/invitation-authorization-mismatch/);
    expect(adapter.authorize).toHaveBeenCalledTimes(1);
    expect(adapter.deliver).not.toHaveBeenCalled();
  });

  it("rejects a substituted link artifact before contacting Node or OpenCredentials", async () => {
    const share = await generatedShare();
    const adapter = adapterFor();
    const substituted = {...share, shareUrl: `${share.shareUrl}&link=substituted`} as ShareArtifact;

    await expect(sendShareEmail({share: substituted, scope, adapters: adapter})).rejects.toThrow(/generated exact-email link/);
    expect(adapter.authorize).not.toHaveBeenCalled();
    expect(adapter.deliver).not.toHaveBeenCalled();
  });
});
