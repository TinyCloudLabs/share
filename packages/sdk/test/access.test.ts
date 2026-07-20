import { createHash } from "node:crypto";
import { ed25519 } from "@noble/curves/ed25519";
import { describe, expect, it, vi } from "vitest";
import {
  canonicalize,
  computeCid,
  didKeyFromEd25519PublicKey,
  fromBase64Url,
  toBase64Url,
  type ShareEnvelope,
} from "@tinycloud/share-envelope";
import { accessSharedContent } from "../src/access.js";
import {
  canonicalDigest,
  createInvitationDraft,
  SIGNATURE_DOMAINS,
  type ContentSource,
  type SenderScope,
} from "../../../src/email-share/protocol.js";
import {
  ShareTransportError,
  type ReadResponse,
  type ShareTransport,
} from "../../../src/email-share/transport.js";
import { digestText } from "../../../src/email-share/node-verifier.js";
import { resolveShare, type ResolveResult } from "../../../src/viewer/resolve.js";

const senderSeed = new Uint8Array(32).fill(41);
const issuerSeed = new Uint8Array(32).fill(42);
const nodeSeed = new Uint8Array(32).fill(43);
const wrongHolderSeed = new Uint8Array(32).fill(44);
const wrongNodeSeed = new Uint8Array(32).fill(45);
const senderDid = didKeyFromEd25519PublicKey(ed25519.getPublicKey(senderSeed));
const issuerDid = didKeyFromEd25519PublicKey(ed25519.getPublicKey(issuerSeed));
const shareOrigin = "https://share.tinycloud.xyz";
const nodeOrigin = "https://node.example";
const nodeAudience = "did:web:node.example";
const source = {
  kind: "kv",
  space: "did:pkh:eip155:1:0x1111111111111111111111111111111111111111",
  path: "documents/plan.md",
  action: "tinycloud.kv/get",
} as const satisfies ContentSource;
const trustedNode = {
  targetOrigin: nodeOrigin,
  nodeAudience,
  invitationKid: "did:web:node.example#invitation-key-1",
  invitationPublicKey: ed25519.getPublicKey(nodeSeed),
  keyVersion: 1,
  enabled: true as const,
};

function responseProof(
  value: unknown,
  domain: string,
  mode: "valid" | "unsigned" | "wrong-node",
): { alg: "EdDSA"; kid: string; signature: string } {
  if (mode === "unsigned") {
    return { alg: "none" as "EdDSA", kid: "", signature: "" };
  }
  return {
    alg: "EdDSA",
    kid: trustedNode.invitationKid,
    signature: toBase64Url(
      ed25519.sign(
        new TextEncoder().encode(`${domain}${canonicalize(value)}`),
        mode === "wrong-node" ? wrongNodeSeed : nodeSeed,
      ),
    ),
  };
}

async function credentialFor(
  holderDid: string,
  share: VerifiedShare,
): Promise<{ format: "vc+sd-jwt"; credential: string; holderDid: string; expiresAt: string }> {
  const now = Math.floor(Date.now() / 1000);
  const expiresAt = new Date((now + 86_400) * 1000).toISOString();
  const disclosure = toBase64Url(
    new TextEncoder().encode(
      JSON.stringify(["A".repeat(22), "email", "Alice@example.com"]),
    ),
  );
  const disclosureDigest = createHash("sha256")
    .update(disclosure)
    .digest("base64url");
  const header = toBase64Url(
    new TextEncoder().encode(JSON.stringify({ alg: "EdDSA" })),
  );
  const payload = toBase64Url(
    new TextEncoder().encode(
      JSON.stringify({
        iss: issuerDid,
        sub: holderDid,
        iat: now,
        nbf: now,
        exp: Math.floor(Date.parse(expiresAt) / 1000),
        vct: "opencredentials.email/v1",
        jti: "credential-test",
        tinycloud_share: {
          share_cid: share.shareCid,
          share_id: share.shareId,
          policy_cid: share.policyCid,
          node_audience: share.nodeAudience,
        },
        _sd_alg: "sha-256",
        _sd: [disclosureDigest],
      }),
    ),
  );
  const signature = toBase64Url(
    ed25519.sign(
      new TextEncoder().encode(`${header}.${payload}`),
      issuerSeed,
    ),
  );
  return {
    format: "vc+sd-jwt",
    credential: `${header}.${payload}.${signature}~${disclosure}~`,
    holderDid,
    expiresAt,
  };
}

type VerifiedShare = {
  readonly shareId: string;
  readonly shareCid: string;
  readonly policyCid: string;
  readonly recipientEmail: string;
  readonly recipientHint: string;
  readonly expiry: string;
  readonly nodeOrigin: string;
  readonly nodeAudience: string;
  readonly requestOrigin: string;
  readonly delegationCid: string;
  readonly authorityMaterialHandle: string;
  readonly authorityMaterialDigest: string;
  readonly contentSource: ContentSource;
  readonly contentSourceDigest: string;
  readonly action: "tinycloud.kv/get";
  readonly resource: string;
  readonly trustedNode: typeof trustedNode;
};

async function makeHarness(options: {
  readonly proofMode?: "valid" | "unsigned" | "wrong-node";
  readonly proofFailure?: { readonly stage: "challenge" | "session" | "read"; readonly mode: "unsigned" | "wrong-node" };
  readonly holderMode?: "valid" | "wrong-holder";
  readonly replay?: boolean;
} = {}) {
  const proofModeFor = (stage: "challenge" | "session" | "read"): "valid" | "unsigned" | "wrong-node" => options.proofFailure?.stage === stage ? options.proofFailure.mode : options.proofMode ?? "valid";
  let sealedBlob: Uint8Array | undefined;
  const draft = await createInvitationDraft({
    email: "Alice@example.com",
    source,
    scope: {
      policyOwnerDid:
        "did:pkh:eip155:1:0x2222222222222222222222222222222222222222",
      senderDid,
      signingCapability: {
        capabilityId: "A".repeat(22),
        publicKey: ed25519.getPublicKey(senderSeed),
      },
      signer: {
        publicKey: ed25519.getPublicKey(senderSeed),
        sign: async ({ message }) =>
          ed25519.sign(
            new TextEncoder().encode(
              `${SIGNATURE_DOMAINS.envelope}${message}`,
            ),
            senderSeed,
          ),
      },
      shareOrigin,
      delegation: "opaque-policy-delegation",
      delegationCid: "bafkreihdwdcefgh4dqkjv67uzcmw7jeh4qjv4x7l2qqx3g7u3s4q3bqz3y",
      authorityMaterialHandle: "amh_kv_001",
      authorityMaterialDigest: "B".repeat(43),
      targetOrigin: nodeOrigin,
      nodeAudience,
      spaceId: source.space,
      documentName: "Project plan.md",
      senderTrust: "verified",
      trustedNode,
    } satisfies SenderScope,
    shareId: "share-access-test",
    expiresAt: new Date(Date.now() + 86_400_000).toISOString(),
    uploadEnvelope: async (_cid, blob) => {
      sealedBlob = blob;
    },
  });

  const resolvedShare = {
    shareId: draft.envelope.shareId,
    shareCid: draft.shareCid,
    policyCid: draft.policyCid,
    recipientEmail: draft.email,
    recipientHint: draft.envelope.display.recipientHint ?? "",
    expiry: draft.envelope.expiry,
    nodeOrigin,
    nodeAudience,
    requestOrigin: shareOrigin,
    delegationCid:
      "bafkreihdwdcefgh4dqkjv67uzcmw7jeh4qjv4x7l2qqx3g7u3s4q3bqz3y",
    authorityMaterialHandle: "amh_kv_001",
    authorityMaterialDigest: "B".repeat(43),
    contentSource: source,
    contentSourceDigest: await canonicalDigest(source),
    action: source.action,
    resource: source.path,
    trustedNode,
  } satisfies VerifiedShare;

  let redeemCount = 0;
  let activeCredentialDigest = "";
  const transport: ShareTransport = {
    authorizeInvitation: async () => {
      throw new Error("unused");
    },
    requestDelivery: async () => {
      throw new Error("unused");
    },
    resend: async () => {
      throw new Error("unused");
    },
    activate: vi.fn(async () => ({
      status: "accepted" as const,
      retryAfterSeconds: 20,
      activationId: "A".repeat(22),
    })),
    claimChallenge: vi.fn(async () => ({
      claimNonce: "C".repeat(43),
      shareCid: resolvedShare.shareCid,
      shareId: resolvedShare.shareId,
      policyCid: resolvedShare.policyCid,
      delegationCid: resolvedShare.delegationCid,
      authorityMaterialHandle: resolvedShare.authorityMaterialHandle,
      authorityMaterialDigest: resolvedShare.authorityMaterialDigest,
      contentSource: source,
      contentSourceDigest: resolvedShare.contentSourceDigest,
      emailHash: "D".repeat(43),
      targetOrigin: nodeOrigin,
      nodeAudience,
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
    })),
    claimRedeem: vi.fn(async (body) => {
      if (options.replay && redeemCount++ > 0) {
        throw new ShareTransportError("used");
      }
      const binding = body.binding as Record<string, unknown>;
      const holderDid =
        options.holderMode === "wrong-holder"
          ? didKeyFromEd25519PublicKey(ed25519.getPublicKey(wrongHolderSeed))
          : String(binding.holderDid);
      return credentialFor(holderDid, resolvedShare);
    }),
    policyChallenge: vi.fn(async (body) => {
      const request = body as Record<string, unknown>;
      const challenge = {
        type: "TinyCloudSharePolicyChallenge",
        version: 1,
        challengeId: "E".repeat(22),
        nonce: "F".repeat(43),
        ...request,
        issuedAt: new Date().toISOString(),
        expiresAt: new Date(Date.now() + 119_000).toISOString(),
      };
      return {
        challenge,
        proof:
          responseProof(challenge, SIGNATURE_DOMAINS.policyChallenge, proofModeFor("challenge")),
      };
    }),
    policySession: vi.fn(async (body) => {
      const presentation = body.presentation as Record<string, unknown>;
      const session = {
        type: "TinyCloudSharePolicySession",
        version: 1,
        sessionId: "G".repeat(22),
        shareCid: presentation.shareCid,
        shareId: presentation.shareId,
        delegationCid: presentation.delegationCid,
        policyCid: presentation.policyCid,
        authorityMaterialHandle: presentation.authorityMaterialHandle,
        authorityMaterialDigest: presentation.authorityMaterialDigest,
        contentSource: presentation.contentSource,
        contentSourceDigest: presentation.contentSourceDigest,
        holderDid: presentation.holderDid,
        targetOrigin: presentation.targetOrigin,
        nodeAudience: presentation.nodeAudience,
        action: presentation.action,
        resource: presentation.resource,
        credentialDigest: (activeCredentialDigest = await digestText(String(body.credential))),
        issuedAt: new Date().toISOString(),
        expiresAt: new Date(Date.now() + 300_000).toISOString(),
      };
      return {
        session,
        proof: responseProof(
          session,
          SIGNATURE_DOMAINS.policySession,
          proofModeFor("session"),
        ),
      };
    }),
    read: vi.fn(async (body) => {
      const invocation = body.invocation as Record<string, unknown>;
      const content = "# authoritative plan\n";
      const response: Omit<ReadResponse, "proof"> = {
        type: "TinyCloudShareReadResponse",
        version: 1,
        sessionId: String(invocation.sessionId),
        requestJti: String(invocation.jti),
        readJti: "H".repeat(22),
        audience: nodeAudience,
        holderDid: String(invocation.holderDid),
        credentialDigest: activeCredentialDigest,
        issuedAt: new Date().toISOString(),
        expiresAt: new Date(Date.now() + 30_000).toISOString(),
        mediaType: "text/markdown; charset=utf-8" as const,
        content,
        contentSource: source,
        contentSourceDigest: resolvedShare.contentSourceDigest,
        action: source.action,
        resource: source.path,
        requestBodyDigest: String(body.requestBodyDigest),
        bodyDigest: await digestText(content),
        delegationCid: resolvedShare.delegationCid,
        authorityMaterialHandle: resolvedShare.authorityMaterialHandle,
        authorityMaterialDigest: resolvedShare.authorityMaterialDigest,
      };
      return {
        ...response,
        proof: responseProof(
          response,
          SIGNATURE_DOMAINS.readResponse,
          proofModeFor("read"),
        ),
      };
    }),
  };

  const registryFetch = vi.fn(async () =>
    new Response(
      sealedBlob === undefined
        ? null
        : Buffer.from(sealedBlob),
      {
      status: 200,
      headers: { "content-type": "application/vnd.ipld.raw" },
      },
    ),
  );
  const resolve = async (href: string, input: { registryBaseUrl: string }): Promise<ResolveResult> =>
    resolveShare(href, { registryBaseUrl: input.registryBaseUrl, fetchFn: registryFetch });
  const verifyShare = async (input: {
    envelope: ShareEnvelope;
    shareCid: string;
    policy: Record<string, unknown>;
  }): Promise<VerifiedShare> => {
    if (input.shareCid !== resolvedShare.shareCid) throw new Error("share-cid-mismatch");
    if (input.envelope.authorizationTarget.kind !== "policy") {
      throw new Error("policy-target-required");
    }
    const policyBytes = fromBase64Url(input.envelope.authorizationTarget.policyBytes);
    if (
      await computeCid(policyBytes) !== input.envelope.authorizationTarget.policyCid ||
      canonicalize(input.policy.contentSource) !== canonicalize(source) ||
      input.policy.contentSourceDigest !== resolvedShare.contentSourceDigest
    ) {
      throw new Error("policy-source-mismatch");
    }
    return resolvedShare;
  };

  return {
    draft,
    shareUrl: `${draft.shareUrl}&i=${"I".repeat(22)}&c=${"C".repeat(43)}`,
    transport,
    dependencies: {
      resolve,
      verifyShare,
      credentialTrust: {
        issuerDid,
        vct: "opencredentials.email/v1" as const,
        issuerPublicKey: ed25519.getPublicKey(issuerSeed),
      },
      transport,
      registryBaseUrl: "https://registry.example",
      scrub: () => undefined,
    },
  };
}

describe("content access SDK", () => {
  it("captures and scrubs synchronously, then reaches authoritative content only after confirmation", async () => {
    const harness = await makeHarness();
    const order: string[] = [];
    const result = await accessSharedContent({
      shareUrl: harness.shareUrl,
      confirmAccess: () => {
        order.push("confirm");
        return true;
      },
      dependencies: {
        ...harness.dependencies,
        scrub: () => order.push("scrub"),
      },
    });

    expect(result.content).toBe("# authoritative plan\n");
    expect(result.shareCid).toBe(harness.draft.shareCid);
    expect(result.holderDid).toMatch(/^did:key:z/);
    expect(order.slice(0, 2)).toEqual(["scrub", "confirm"]);
  });

  it("does not redeem when scanner-safe confirmation is denied", async () => {
    const harness = await makeHarness();
    await expect(
      accessSharedContent({
        shareUrl: harness.shareUrl,
        confirmAccess: () => false,
        dependencies: harness.dependencies,
      }),
    ).rejects.toThrow("access-not-confirmed");
    expect(harness.transport.activate).not.toHaveBeenCalled();
    expect(harness.transport.claimRedeem).not.toHaveBeenCalled();
  });

  it("fails closed for a wrong holder, altered link, and altered policy/source", async () => {
    const wrongHolder = await makeHarness({ holderMode: "wrong-holder" });
    await expect(
      accessSharedContent({
        shareUrl: wrongHolder.shareUrl,
        confirmAccess: () => true,
        dependencies: wrongHolder.dependencies,
      }),
    ).rejects.toThrow();

    const altered = await makeHarness();
    const alteredUrl = altered.shareUrl.replace(/#k=.+$/, "#k=" + "Z".repeat(43));
    await expect(
      accessSharedContent({
        shareUrl: alteredUrl,
        confirmAccess: () => true,
        dependencies: altered.dependencies,
      }),
    ).rejects.toThrow();

    const alteredPolicy = await makeHarness();
    await expect(
      accessSharedContent({
        shareUrl: alteredPolicy.shareUrl,
        confirmAccess: () => true,
        dependencies: {
          ...alteredPolicy.dependencies,
          verifyShare: async (input) => {
            const policy = { ...input.policy, contentSource: { ...source, path: "other.md" } };
            if (canonicalize(policy.contentSource) !== canonicalize(source)) {
              throw new Error("policy-source-mismatch");
            }
            throw new Error("policy-source-mismatch");
          },
        },
      }),
    ).rejects.toThrow("policy-source-mismatch");
  });

  it("fails closed on replay and expiry", async () => {
    const replay = await makeHarness({ replay: true });
    const input = {
      shareUrl: replay.shareUrl,
      confirmAccess: () => true,
      dependencies: replay.dependencies,
    };
    await expect(accessSharedContent(input)).resolves.toMatchObject({
      content: "# authoritative plan\n",
    });
    await expect(accessSharedContent(input)).rejects.toThrow();

    const expired = await makeHarness();
    await expect(
      accessSharedContent({
        shareUrl: expired.shareUrl,
        confirmAccess: () => true,
        dependencies: {
          ...expired.dependencies,
          resolve: async () => ({
            state: "expired",
            envelope: expired.draft.envelope,
          }),
        },
      }),
    ).rejects.toThrow("share-access-expired");
  });

  it("rejects each unsigned and wrong-node response independently", async () => {
    for (const stage of ["challenge", "session", "read"] as const) {
      for (const mode of ["unsigned", "wrong-node"] as const) {
        const harness = await makeHarness({ proofFailure: { stage, mode } });
        await expect(
          accessSharedContent({
            shareUrl: harness.shareUrl,
            confirmAccess: () => true,
            dependencies: harness.dependencies,
          }),
        ).rejects.toThrow();
      }
    }
  });
});
