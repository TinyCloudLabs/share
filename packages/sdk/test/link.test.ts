import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { ed25519 } from "@noble/curves/ed25519";
import { secp256k1 } from "@noble/curves/secp256k1";
import { blake3 } from "@noble/hashes/blake3";
import { keccak_256 } from "@noble/hashes/sha3";
import {
  canonicalize,
  didKeyFromEd25519PublicKey,
  fromBase64Url,
  open,
  parseShareUrl,
  shareEnvelopeSchema,
  toBase64Url,
  verifyEnvelope,
} from "@tinycloud/share-envelope";
import { describe, expect, it, vi } from "vitest";

import {
  assertGeneratedShareLink,
  createShareLink,
  type CreateShareLinkInput,
  type GeneratedShareLink,
} from "../src/link.js";
import { SIGNATURE_DOMAINS, type ContentSource, type SenderScope } from "../../../src/email-share/protocol.js";

const vectors = JSON.parse(readFileSync(new URL("../../../test/vectors/email-claim-v1/positive.json", import.meta.url), "utf8")) as {
  readonly scenarios: readonly [{
    readonly source: ContentSource;
    readonly policy: Record<string, unknown>;
    readonly policyBytes: string;
    readonly policyCid: string;
    readonly delegationCid: string;
    readonly authorityMaterial: Readonly<Record<string, unknown>>;
    readonly authorityMaterialDigest: string;
    readonly authorization: { readonly senderDid: string };
    readonly enrollment: { readonly nodeAudience: string; readonly invitationKid: string; readonly invitationPublicKey: string };
  }, ...unknown[]];
};
const fixture = vectors.scenarios[0];
const senderSeed = new Uint8Array(32).fill(0x44);
const senderPublicKey = ed25519.getPublicKey(senderSeed);
const senderDid = didKeyFromEd25519PublicKey(senderPublicKey);
const source = fixture.source;
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

function standardOwnerSignedMaterial(): { readonly material: Readonly<Record<string, unknown>>; readonly digest: string; readonly ownerDid: string } {
  const material = JSON.parse(JSON.stringify(fixture.authorityMaterial)) as Record<string, unknown>;
  for (const key of ["policyAuthorityBytes", "policyEnforcementBytes"] as const) {
    const parent = JSON.parse(new TextDecoder().decode(fromBase64Url(String(material[key])))) as Record<string, unknown>;
    const facts = parent.facts as Record<string, unknown>;
    facts["xyz.tinycloud.policy/ownerDid"] = policyOwnerDid;
    parent.issuerDid = policyOwnerDid;
    delete parent.signature;
    delete parent.delegationCid;
    const unsignedBytes = new TextEncoder().encode(canonicalize(parent));
    const signedDigest = new Uint8Array(createHash("sha256").update(new TextEncoder().encode(`xyz.tinycloud.policy/enforcement-delegation/v1\0`)).update(unsignedBytes).digest());
    const messageHash = keccak_256(new Uint8Array([...new TextEncoder().encode("\x19Ethereum Signed Message:\n32"), ...signedDigest]));
    const signature = secp256k1.sign(messageHash, ownerPrivateKey, { lowS: true });
    const unsignedWithSignature = { ...parent, signature: { suite: "eip191-secp256k1-sha256-jcs-v1", value: toBase64Url(new Uint8Array([...signature.toBytes("compact"), signature.recovery])) } };
    const parentCid = nodeCid(new TextEncoder().encode(canonicalize(unsignedWithSignature)));
    const canonicalBytes = new TextEncoder().encode(canonicalize({ ...unsignedWithSignature, delegationCid: parentCid }));
    material[key] = toBase64Url(canonicalBytes);
    material[key.replace("Bytes", "Cid")] = parentCid;
  }
  material.policyOwnerDid = policyOwnerDid;
  material.relationship = { policyOwnerDid, senderDid, authenticated: true };
  const mapping = material.mapping as Record<string, unknown>;
  mapping.policyAuthorityCid = material.policyAuthorityCid;
  mapping.policyEnforcementCid = material.policyEnforcementCid;
  for (const status of material.statusObservations as Array<Record<string, unknown>>) status.parentCid = status.parentCid === fixture.authorityMaterial.policyAuthorityCid ? material.policyAuthorityCid : material.policyEnforcementCid;
  const nodeSeed = new Uint8Array(32).fill(0x42);
  const nodeDid = didKeyFromEd25519PublicKey(ed25519.getPublicKey(nodeSeed));
  const statusDomain = "xyz.tinycloud.share/authority-status/v1\0";
  for (const status of material.statusObservations as Array<Record<string, unknown>>) {
    status.checkedAt = "2026-07-20T11:59:00.000Z";
    status.freshUntil = "2026-07-20T12:04:00.000Z";
    status.signerKid = `${nodeDid}#${nodeDid.slice("did:key:".length)}`;
    const unsigned = { ...status };
    delete unsigned.signature;
    status.signature = { alg: "EdDSA", kid: status.signerKid, value: toBase64Url(ed25519.sign(new TextEncoder().encode(`${statusDomain}${canonicalize(unsigned)}`), nodeSeed)) };
  }
  const attestation = material.attestation as Record<string, unknown>;
  attestation.expiresAt = "2026-07-23T12:04:00.000Z";
  const unsignedAttestation = { ...attestation };
  delete unsignedAttestation.signature;
  attestation.signature = { alg: "EdDSA", kid: String(attestation.localSignerKid), value: toBase64Url(ed25519.sign(new TextEncoder().encode(`xyz.tinycloud.share/enrollment-attestation/v1\0${canonicalize(unsignedAttestation)}`), nodeSeed)) };
  const digest = createHash("sha256").update(canonicalize(material)).digest("base64url");
  return { material, digest, ownerDid: policyOwnerDid };
}
const standardMaterial = standardOwnerSignedMaterial();
const scope: SenderScope = {
  policyOwnerDid: standardMaterial.ownerDid,
  senderDid,
  signingCapability: { capabilityId: "A".repeat(22), publicKey: senderPublicKey },
  signer: {
    publicKey: senderPublicKey,
    sign: async (input) => ed25519.sign(new TextEncoder().encode(`${SIGNATURE_DOMAINS.envelope}${input.message}`), senderSeed),
  },
  shareOrigin: "https://share.tinycloud.xyz",
  delegation: "uCAESA.kv.terminal",
  delegationCid: fixture.delegationCid,
  authorityMaterialHandle: "amh_kv_001",
  authorityMaterialDigest: standardMaterial.digest,
  targetOrigin: "https://node.example",
  nodeAudience: "did:web:node.example",
  spaceId: source.space,
  documentName: "Project plan.md",
  senderTrust: "verified",
  trustedNode: {
    targetOrigin: "https://node.example",
    nodeAudience: "did:web:node.example",
    invitationKid: fixture.enrollment.invitationKid,
    invitationPublicKey: fromBase64Url(fixture.enrollment.invitationPublicKey),
    keyVersion: 1,
    enabled: true,
  },
  authorityMaterial: standardMaterial.material,
};

const policyDigest = createHash("sha256").update(fromBase64Url(fixture.policyBytes)).digest("base64url");
const authoritativePolicy = {
  recipientEmail: String(fixture.policy.recipientEmail),
  source,
  action: source.action,
  resource: source.path,
  expiresAt: String(fixture.policy.expiresAt),
  target: { origin: scope.targetOrigin, nodeAudience: scope.nodeAudience, spaceId: scope.spaceId },
  policyCid: fixture.policyCid,
  policyDigest,
  policyBytes: fixture.policyBytes,
  contentSourceDigest: String(fixture.policy.contentSourceDigest),
  delegationCid: scope.delegationCid,
  authorityMaterialDigest: scope.authorityMaterialDigest,
  policyAuthorityCid: String(scope.authorityMaterial?.policyAuthorityCid),
  policyAuthorityBytes: String(scope.authorityMaterial?.policyAuthorityBytes),
  policyEnforcementCid: String(scope.authorityMaterial?.policyEnforcementCid),
  policyEnforcementBytes: String(scope.authorityMaterial?.policyEnforcementBytes),
};

function request(overrides: Partial<CreateShareLinkInput> = {}): CreateShareLinkInput {
  return {
    email: "Alice+Notes@EXAMPLE.COM",
    source,
    scope,
    shareId: "share-sdk-test",
    expiresAt: "2026-07-23T12:00:00.000Z",
    now: "2026-07-20T12:00:00.000Z",
    adapters: { uploadEnvelope: vi.fn(async () => undefined) },
    policy: authoritativePolicy,
    ...overrides,
  };
}

function authorityScopeWithParentMutation(mutate: (parent: Record<string, unknown>) => void): SenderScope {
  const material = { ...scope.authorityMaterial } as Record<string, unknown>;
  const parent = JSON.parse(new TextDecoder().decode(fromBase64Url(String(material.policyEnforcementBytes)))) as Record<string, unknown>;
  mutate(parent);
  material.policyEnforcementBytes = toBase64Url(new TextEncoder().encode(canonicalize(parent)));
  const authorityMaterialDigest = createHash("sha256").update(canonicalize(material)).digest("base64url");
  return { ...scope, authorityMaterial: material, authorityMaterialDigest };
}

function authorityScopeWithMaterialMutation(mutate: (material: Record<string, unknown>) => void): SenderScope {
  const material = JSON.parse(JSON.stringify(scope.authorityMaterial)) as Record<string, unknown>;
  mutate(material);
  return { ...scope, authorityMaterial: material, authorityMaterialDigest: createHash("sha256").update(canonicalize(material)).digest("base64url") };
}

describe("link-generation SDK lane", () => {
  it("generates a verified policy envelope and performs no mail/provider work", async () => {
    const uploadEnvelope = vi.fn(async (_cid: string, _blob: Uint8Array, _deleteAfter: string) => undefined);
    const publishBinding = vi.fn(async (_binding: Record<string, unknown>) => undefined);
    const mail = vi.fn();
    const provider = vi.fn();
    const result = await createShareLink(request({ adapters: { uploadEnvelope, publishBinding } }));

    expect(uploadEnvelope).toHaveBeenCalledTimes(1);
    expect(mail).not.toHaveBeenCalled();
    expect(provider).not.toHaveBeenCalled();
    expect(result.recipientEmail).toBe("Alice+Notes@example.com");
    expect(result.action).toBe("tinycloud.kv/get");
    expect(result.resource).toBe(source.path);
    expect(result.provenance).toMatchObject({
      senderDid,
      delegationCid: scope.delegationCid,
      authorityMaterialHandle: scope.authorityMaterialHandle,
      target: { origin: scope.targetOrigin, nodeAudience: scope.nodeAudience, spaceId: scope.spaceId },
    });
    expect(result.policyDigest).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(result.provenance).toMatchObject({
      policyCid: result.policyCid,
      policyDigest: result.policyDigest,
      contentSourceDigest: expect.stringMatching(/^[A-Za-z0-9_-]{43}$/),
      delegationCid: scope.delegationCid,
      authorityMaterialDigest: scope.authorityMaterialDigest,
    });
    expect(JSON.stringify(result)).not.toMatch(/private|claimSecret|reportAbuseToken|invitationJti/i);

    const { ciphertextCid, key32 } = parseShareUrl(result.shareUrl, { expectedOrigin: scope.shareOrigin });
    const blob = uploadEnvelope.mock.calls[0]?.[1];
    expect(blob).toBeDefined();
    const envelope = shareEnvelopeSchema.parse(JSON.parse(new TextDecoder().decode(await open(blob!, key32))));
    expect(ciphertextCid).toBe(result.shareCid);
    expect(envelope.authorizationTarget.kind).toBe("policy");
    expect(envelope.delegation).toBe(scope.delegation);
    expect(envelope.target).toEqual({
      origin: scope.targetOrigin,
      nodeAudience: scope.nodeAudience,
      spaceId: scope.spaceId,
      resource: { kind: "exact", path: source.path },
    });
    expect(envelope.expiry).toBe(result.expiresAt);
    if (envelope.authorizationTarget.kind !== "policy") throw new Error("expected policy target");
    const policy = JSON.parse(new TextDecoder().decode(fromBase64Url(envelope.authorizationTarget.policyBytes))) as Record<string, unknown>;
    expect(policy).toMatchObject({
      recipientEmail: "Alice+Notes@example.com",
      action: source.action,
      resource: source.path,
      expiresAt: result.expiresAt,
      contentSource: source,
      contentSourceDigest: result.provenance.contentSourceDigest,
    });
    expect(policy).not.toHaveProperty("policyCid");
    expect(policy).not.toHaveProperty("shareCid");
    expect(envelope).not.toHaveProperty("content");
    expect(publishBinding).toHaveBeenCalledWith(expect.objectContaining({
      policyCid: result.policyCid,
      policyDigest: result.policyDigest,
      delegationCid: scope.delegationCid,
      authorityMaterialDigest: scope.authorityMaterialDigest,
      recipientEmail: "Alice+Notes@example.com",
      action: source.action,
      resource: source.path,
      expiry: result.expiresAt,
    }));
    await expect(verifyEnvelope(envelope, { expectedSignerDid: senderDid })).resolves.toBe(true);

  });

  it("rejects recipient, policy, source, action, expiry, and target substitutions before upload", async () => {
    const cases: Array<Partial<CreateShareLinkInput>> = [
      { email: " Alice@example.com" },
      { policy: { ...authoritativePolicy, recipientEmail: "Mallory@example.com" } },
      { policy: { ...authoritativePolicy, source: { ...source, path: "documents/other.md" }, resource: "documents/other.md" } },
      { policy: { ...authoritativePolicy, action: "tinycloud.sql/read" as const } },
      { policy: { ...authoritativePolicy, resource: "documents/other.md" } },
      { policy: { ...authoritativePolicy, expiresAt: "2026-07-24T12:00:00.000Z" } },
      { policy: { ...authoritativePolicy, target: { origin: "https://other.example", nodeAudience: scope.nodeAudience, spaceId: scope.spaceId } } },
      { source: { ...source, action: "tinycloud.sql/read" as never } },
      { expiresAt: "2026-07-19T12:00:00.000Z" },
      { target: { origin: "https://other.example", nodeAudience: scope.nodeAudience, spaceId: scope.spaceId } },
      { scope: { ...scope, senderDid: "did:key:z6Mkwrong" } },
      { scope: { ...scope, trustedNode: { ...scope.trustedNode, targetOrigin: "https://other.example" } } },
      { scope: { ...scope, nodeAudience: "did:web:other.example" } },
      { scope: { ...scope, spaceId: "spaces/alias" } },
      { scope: { ...scope, expiryMin: "2026-07-24T00:00:00.000Z" } },
      { scope: { ...scope, expiryMax: "2026-07-22T00:00:00.000Z" } },
      { scope: { ...scope, expiresAt: "2026-07-22T00:00:00.000Z" } },
    ];

    for (const overrides of cases) {
      const uploadEnvelope = vi.fn(async () => undefined);
      await expect(createShareLink(request({ ...overrides, adapters: { uploadEnvelope } }))).rejects.toThrow();
      expect(uploadEnvelope).not.toHaveBeenCalled();
    }
  });

  it("requires an authoritative policy and does no network work before validation", async () => {
    const uploadEnvelope = vi.fn(async () => undefined);
    const publishBinding = vi.fn(async () => undefined);
    await expect(createShareLink(request({ policy: undefined, adapters: { uploadEnvelope, publishBinding } }))).rejects.toThrow(/authoritative policy/i);
    expect(uploadEnvelope).not.toHaveBeenCalled();
    expect(publishBinding).not.toHaveBeenCalled();
  });

  it("recomputes policy CID and digest from supplied bytes", async () => {
    const changedPolicy = JSON.parse(new TextDecoder().decode(fromBase64Url(fixture.policyBytes))) as Record<string, unknown>;
    changedPolicy.resource = "documents/other.md";
    const alteredBytes = toBase64Url(new TextEncoder().encode(canonicalize(changedPolicy)));
    const cases: Array<Partial<CreateShareLinkInput>> = [
      { policy: { ...authoritativePolicy, policyBytes: alteredBytes } },
      { policy: { ...authoritativePolicy, policyCid: authoritativePolicy.policyCid.replace(/.$/, "a") } },
      { policy: { ...authoritativePolicy, policyDigest: "A".repeat(43) } },
    ];
    for (const overrides of cases) {
      const uploadEnvelope = vi.fn(async () => undefined);
      await expect(createShareLink(request({ ...overrides, adapters: { uploadEnvelope } }))).rejects.toThrow();
      expect(uploadEnvelope).not.toHaveBeenCalled();
    }
  });

  it("rejects altered owner-signed delegation bytes with a retained CID", async () => {
    const uploadEnvelope = vi.fn(async () => undefined);
    const mutatedScope = authorityScopeWithParentMutation((parent) => { parent.audienceDid = "did:key:z6Mkwwrong"; });
    await expect(createShareLink(request({ scope: mutatedScope, policy: { ...authoritativePolicy, authorityMaterialDigest: mutatedScope.authorityMaterialDigest }, adapters: { uploadEnvelope } }))).rejects.toThrow(/CID|audience|signature/i);
    expect(uploadEnvelope).not.toHaveBeenCalled();
  });

  it("rejects wrong policy owner and enforcer/audience bindings", async () => {
    const cases: Array<Partial<CreateShareLinkInput>> = [
      { scope: { ...scope, policyOwnerDid: "did:pkh:eip155:1:0x3333333333333333333333333333333333333333" } },
      { scope: { ...scope, nodeAudience: "did:web:wrong.example" } },
      { scope: { ...scope, targetOrigin: "https://wrong.example", trustedNode: { ...scope.trustedNode, targetOrigin: "https://wrong.example" } } },
    ];
    for (const overrides of cases) {
      const uploadEnvelope = vi.fn(async () => undefined);
      await expect(createShareLink(request({ ...overrides, adapters: { uploadEnvelope } }))).rejects.toThrow();
      expect(uploadEnvelope).not.toHaveBeenCalled();
    }
  });

  it("rejects policy and enforcement-delegation substitutions before upload", async () => {
    const baseline = await createShareLink(request());
    const policy = { ...authoritativePolicy, expiresAt: baseline.expiresAt, target: baseline.target, policyCid: baseline.policyCid, policyDigest: baseline.policyDigest, contentSourceDigest: baseline.provenance.contentSourceDigest };
    const cases: Array<Partial<CreateShareLinkInput>> = [
      { policy: { ...policy, policyCid: baseline.shareCid } },
      { policy: { ...policy, policyDigest: "B".repeat(43) } },
      { policy: { ...policy, delegationCid: "bafkreiaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" } },
      { policy: { ...policy, authorityMaterialDigest: "B".repeat(43) } },
      { scope: { ...scope, delegationCid: "bafkreiaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }, policy },
      { scope: { ...scope, authorityMaterialDigest: "B".repeat(43) }, policy },
    ];
    for (const overrides of cases) {
      const uploadEnvelope = vi.fn(async () => undefined);
      await expect(createShareLink(request({ ...overrides, adapters: { uploadEnvelope } }))).rejects.toThrow();
      expect(uploadEnvelope).not.toHaveBeenCalled();
    }
  });

  it("rejects enrollment key, kid, and version substitutions without network access", async () => {
    const cases = [
      authorityScopeWithMaterialMutation((material) => { (material.enrollment as Record<string, unknown>).invitationPublicKey = "A".repeat(43); }),
      authorityScopeWithMaterialMutation((material) => { (material.enrollment as Record<string, unknown>).invitationKid = "did:web:node.example#retired-key"; }),
      authorityScopeWithMaterialMutation((material) => { (material.enrollment as Record<string, unknown>).keyVersion = 2; }),
    ];
    for (const mutatedScope of cases) {
      const uploadEnvelope = vi.fn(async () => undefined);
      const publishBinding = vi.fn(async () => undefined);
      await expect(createShareLink(request({ scope: mutatedScope, policy: { ...authoritativePolicy, authorityMaterialDigest: mutatedScope.authorityMaterialDigest }, adapters: { uploadEnvelope, publishBinding } }))).rejects.toThrow();
      expect(uploadEnvelope).not.toHaveBeenCalled();
      expect(publishBinding).not.toHaveBeenCalled();
    }
  });

  it("rejects wrong enforcer, local signer, and runtime attestation bindings", async () => {
    const cases = [
      (material: Record<string, unknown>) => { (material.attestation as Record<string, unknown>).enforcerDid = "did:key:z6Mkwrong"; },
      (material: Record<string, unknown>) => { (material.attestation as Record<string, unknown>).localSignerDid = "did:key:z6Mkwrong"; },
      (material: Record<string, unknown>) => { (material.attestation as Record<string, unknown>).targetOrigin = "https://wrong.example"; },
    ];
    for (const mutate of cases) {
      const mutatedScope = authorityScopeWithMaterialMutation(mutate);
      const uploadEnvelope = vi.fn(async () => undefined);
      await expect(createShareLink(request({ scope: mutatedScope, policy: { ...authoritativePolicy, authorityMaterialDigest: mutatedScope.authorityMaterialDigest }, adapters: { uploadEnvelope } }))).rejects.toThrow();
      expect(uploadEnvelope).not.toHaveBeenCalled();
    }
  });

  it("rejects missing policy bytes, CID, digest, or owner-parent identifiers before any network call", async () => {
    for (const field of ["policyBytes", "policyCid", "policyDigest", "policyAuthorityCid", "policyAuthorityBytes", "policyEnforcementCid", "policyEnforcementBytes"] as const) {
      const policy = { ...authoritativePolicy } as Record<string, unknown>;
      delete policy[field];
      const uploadEnvelope = vi.fn(async () => undefined);
      await expect(createShareLink(request({ policy: policy as CreateShareLinkInput["policy"], adapters: { uploadEnvelope } }))).rejects.toThrow();
      expect(uploadEnvelope).not.toHaveBeenCalled();
    }
  });

  it("authenticates attestation/status evidence, freshness, and binding digests before upload", async () => {
    const cases = [
      (material: Record<string, unknown>) => { (material.attestation as Record<string, unknown>).signature = { alg: "EdDSA", kid: String((material.attestation as Record<string, unknown>).localSignerKid), value: "A".repeat(86) }; },
      (material: Record<string, unknown>) => { (material.attestation as Record<string, unknown>).expiresAt = "2026-07-19T12:00:00.000Z"; },
      (material: Record<string, unknown>) => { (material.attestation as Record<string, unknown>).measurementDigest = "A".repeat(43); },
      (material: Record<string, unknown>) => { const status = (material.statusObservations as Array<Record<string, unknown>>)[0]!; status.freshUntil = "2026-07-19T12:04:00.000Z"; },
      (material: Record<string, unknown>) => { const status = (material.statusObservations as Array<Record<string, unknown>>)[0]!; status.signature = { alg: "EdDSA", kid: String(status.signerKid), value: "A".repeat(86) }; },
    ];
    for (const mutate of cases) {
      const mutatedScope = authorityScopeWithMaterialMutation(mutate);
      const uploadEnvelope = vi.fn(async () => undefined);
      const publishBinding = vi.fn(async () => undefined);
      await expect(createShareLink(request({ scope: mutatedScope, policy: { ...authoritativePolicy, authorityMaterialDigest: mutatedScope.authorityMaterialDigest }, adapters: { uploadEnvelope, publishBinding } }))).rejects.toThrow();
      expect(uploadEnvelope).not.toHaveBeenCalled();
      expect(publishBinding).not.toHaveBeenCalled();
    }
  });

  it("rejects a substituted link artifact without network access", async () => {
    const link = await createShareLink(request());
    const substituted = { ...link, shareUrl: link.shareUrl.replace("#k=", "?k=") } as GeneratedShareLink;

    expect(() => assertGeneratedShareLink(substituted)).toThrow();
    expect(() => assertGeneratedShareLink(link)).not.toThrow();
  });
});
