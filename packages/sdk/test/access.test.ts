import { createHash } from "node:crypto";
import { ed25519 } from "@noble/curves/ed25519";
import { describe, expect, it, vi } from "vitest";
import {
  canonicalize,
  computeCid,
  didKeyFromEd25519PublicKey,
  ed25519PublicKeyFromDidKey,
  fromBase64Url,
  toBase64Url,
  verifyEnvelope,
  type ShareEnvelope,
} from "@tinycloud/share-envelope";
import { accessSharedContent } from "../src/access.js";
import {
  SIGNATURE_DOMAINS,
  type ContentSource,
} from "../../../src/email-share/protocol.js";
import {
  ShareTransportError,
  type ReadResponse,
  type ShareTransport,
} from "../../../src/email-share/transport.js";
import { digestText } from "../../../src/email-share/node-verifier.js";
import type { ResolveResult } from "../../../src/viewer/resolve.js";

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
const policyCid = "bafkreidu2yzz6wjdmxawbwhzgmard52wzvlkjofxsujkk6sx7zps3fevsu";
const enforcementDelegationCid = "bafkreihdwdcefgh4dqkjv67uzcmw7jeh4qjv4x7l2qqx3g7u3s4q3bqz3y";
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

/** Frozen contract input. Payload creation is covered by the sender lane. */
const policyContract = {
  policy: {
    type: "TinyCloudSharePolicy",
    version: 1,
    recipientEmail: "sam@tinycloud.xyz",
    contentSource: source,
    contentSourceDigest: "B-O75gHmIx2CyOm9cOdHJivP-kupRtNWcUPXuZbEnZ4",
    action: "tinycloud.kv/get",
    resource: "documents/plan.md",
    expiresAt: "2099-01-01T00:00:00.000Z",
    issuerDid: senderDid,
  },
  envelope: {
    version: 1,
    shareId: "share-access-contract-0001",
    delegation: "pre-generated-policy-delegation",
    authorizationTarget: {
      kind: "policy" as const,
      policyCid,
      policyBytes:
        "eyJhY3Rpb24iOiJ0aW55Y2xvdWQua3YvZ2V0IiwiY29udGVudFNvdXJjZSI6eyJhY3Rpb24iOiJ0aW55Y2xvdWQua3YvZ2V0Iiwia2luZCI6Imt2IiwicGF0aCI6ImRvY3VtZW50cy9wbGFuLm1kIiwic3BhY2UiOiJkaWQ6cGtoOmVpcDE1NToxOjB4MTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMSJ9LCJjb250ZW50U291cmNlRGlnZXN0IjoiQi1PNzVnSG1JeDJDeU9tOWNPZEhKaXZQLWt1cFJ0TldjVVBYdVpiRW5aNCIsImV4cGlyZXNBdCI6IjIwOTktMDEtMDFUMDA6MDA6MDAuMDAwWiIsImlzc3VlckRpZCI6ImRpZDprZXk6ejZNa3dKRnB2SlZGZTE1eWdHZ1lMVFl1aVB3Zmhra0RSa01HNGVLUUZUOGc2NXlFIiwicmVjaXBpZW50RW1haWwiOiJzYW1AdGlueWNsb3VkLnh5eiIsInJlc291cmNlIjoiZG9jdW1lbnRzL3BsYW4ubWQiLCJ0eXBlIjoiVGlueUNsb3VkU2hhcmVQb2xpY3kiLCJ2ZXJzaW9uIjoxfQ",
    },
    target: {
      origin: nodeOrigin,
      nodeAudience,
      spaceId: source.space,
      resource: { kind: "exact" as const, path: source.path },
    },
    display: {
      senderName: "TinyCloud sender",
      filename: "Project plan.md",
      recipientHint: "s***@tinycloud.xyz",
    },
    expiry: "2099-01-01T00:00:00.000Z",
    signature: {
      signerDid: senderDid,
      algorithm: "Ed25519" as const,
      value: "uYv_XKyAmrvNifEK2EE2JyMLyoSd4gHh2rayPnSzGz7dqINeBlsK-TNb5vU18nFO1XDFJRwHyUd6cdVHa-8DAg",
    },
  } satisfies ShareEnvelope,
} as const;

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

function assertHolderProof(
  message: unknown,
  proof: unknown,
  domain: string,
  holderDid: string,
): void {
  const value = proof as Record<string, unknown>;
  const expectedKid = `${holderDid}#${holderDid.slice("did:key:".length)}`;
  if (value.alg !== "EdDSA" || value.kid !== expectedKid || typeof value.signature !== "string") {
    throw new ShareTransportError("denied");
  }
  let signature: Uint8Array;
  try {
    signature = fromBase64Url(value.signature);
    if (signature.length !== 64) throw new Error("signature-length");
    if (!ed25519.verify(
      signature,
      new TextEncoder().encode(`${domain}${canonicalize(message)}`),
      ed25519PublicKeyFromDidKey(holderDid),
      { zip215: false },
    )) throw new Error("signature-invalid");
  } catch {
    throw new ShareTransportError("denied");
  }
}

async function credentialFor(
  holderDid: string,
  share: VerifiedShare,
  email = "sam@tinycloud.xyz",
  expiresAt = new Date((Math.floor(Date.now() / 1000) + 86_400) * 1000).toISOString(),
): Promise<{ format: "vc+sd-jwt"; credential: string; holderDid: string; expiresAt: string }> {
  const now = Math.floor(Date.now() / 1000);
  const disclosure = toBase64Url(
    new TextEncoder().encode(
      JSON.stringify(["A".repeat(22), "email", email]),
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
  readonly credentialEmail?: string;
  readonly credentialExpiresAt?: string;
  readonly sessionExpiresAt?: string;
  readonly replay?: boolean;
} = {}) {
  const proofModeFor = (stage: "challenge" | "session" | "read"): "valid" | "unsigned" | "wrong-node" => options.proofFailure?.stage === stage ? options.proofFailure.mode : options.proofMode ?? "valid";
  const resolvedShare = {
    shareId: policyContract.envelope.shareId,
    shareCid: "bafkreihbebwfnvzzqaq7vevdc6jdea3d3eyz4gb42txdkmzxdsaheruhla",
    policyCid,
    recipientEmail: "sam@tinycloud.xyz",
    recipientHint: "s***@tinycloud.xyz",
    expiry: policyContract.envelope.expiry,
    nodeOrigin,
    nodeAudience,
    requestOrigin: shareOrigin,
    delegationCid: enforcementDelegationCid,
    authorityMaterialHandle: "amh_kv_001",
    authorityMaterialDigest: "B".repeat(43),
    contentSource: source,
    contentSourceDigest: policyContract.policy.contentSourceDigest,
    action: source.action,
    resource: source.path,
    trustedNode,
  } satisfies VerifiedShare;

  let redeemCount = 0;
  const readJtis = new Set<string>();
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
      if (
        binding.emailHash !== "D".repeat(43) ||
        binding.policyCid !== policyCid ||
        binding.delegationCid !== enforcementDelegationCid
      ) {
        throw new ShareTransportError("denied");
      }
      assertHolderProof(
        binding,
        body.holderProof,
        SIGNATURE_DOMAINS.holderBinding,
        String(binding.holderDid),
      );
      return credentialFor(
        holderDid,
        resolvedShare,
        options.credentialEmail,
        options.credentialExpiresAt,
      );
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
      if (
        presentation.policyCid !== policyCid ||
        presentation.delegationCid !== enforcementDelegationCid
      ) {
        throw new ShareTransportError("denied");
      }
      assertHolderProof(
        presentation,
        body.proof,
        SIGNATURE_DOMAINS.policyPresentation,
        String(presentation.holderDid),
      );
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
        expiresAt: options.sessionExpiresAt ?? new Date(Date.now() + 300_000).toISOString(),
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
      const invocationJti = String(invocation.jti);
      if (readJtis.has(invocationJti)) throw new ShareTransportError("used");
      readJtis.add(invocationJti);
      assertHolderProof(
        invocation,
        body.proof,
        SIGNATURE_DOMAINS.readInvocation,
        String(invocation.holderDid),
      );
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

  const resolve = async (href: string, _input: { registryBaseUrl: string }): Promise<ResolveResult> => {
    if (href !== "https://share.tinycloud.xyz/s/bafkreihbebwfnvzzqaq7vevdc6jdea3d3eyz4gb42txdkmzxdsaheruhla#k=" + "K".repeat(43)) {
      return { state: "invalid-link", detail: "contract-link-mismatch" };
    }
    return {
      state: "policy-email-claim-required",
      envelope: policyContract.envelope,
      shareCid: resolvedShare.shareCid,
      policy: policyContract.policy,
    };
  };
  const verifyShare = async (input: {
    envelope: ShareEnvelope;
    shareCid: string;
    policy: Record<string, unknown>;
  }): Promise<VerifiedShare> => {
    if (input.shareCid !== resolvedShare.shareCid) throw new Error("share-cid-mismatch");
    if (!(await verifyEnvelope(input.envelope, { expectedSignerDid: senderDid }))) {
      throw new Error("envelope-signature-mismatch");
    }
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
    shareUrl: `https://share.tinycloud.xyz/s/${resolvedShare.shareCid}#k=${"K".repeat(43)}&i=${"I".repeat(22)}&c=${"C".repeat(43)}`,
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
    let finalState: string | undefined;
    let holderKey: CryptoKey | undefined;
    const result = await accessSharedContent({
      shareUrl: harness.shareUrl,
      confirmAccess: () => {
        order.push("confirm");
        return true;
      },
      dependencies: {
        ...harness.dependencies,
        scrub: () => order.push("scrub"),
        onController: (controller) => {
          finalState = controller.state.state;
          controller.subscribe((state) => {
            finalState = state.state;
            if (state.state === "reading") holderKey = state.claim.holder.privateKey;
          });
        },
      },
    });

    expect(result.content).toBe("# authoritative plan\n");
    expect(result.shareCid).toBe("bafkreihbebwfnvzzqaq7vevdc6jdea3d3eyz4gb42txdkmzxdsaheruhla");
    expect(result.holderDid).toMatch(/^did:key:z/);
    expect(order.slice(0, 2)).toEqual(["scrub", "confirm"]);
    expect(finalState).toBe("reading");
    expect(holderKey?.extractable).toBe(false);
    expect(harness.transport.policySession).toHaveBeenCalledWith(
      expect.objectContaining({
        presentation: expect.objectContaining({
          policyCid,
          delegationCid: enforcementDelegationCid,
        }),
      }),
    );
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

  it("independently denies a wrong recipient email, expired credential, and expired session", async () => {
    const wrongEmail = await makeHarness({ credentialEmail: "other@tinycloud.xyz" });
    await expect(
      accessSharedContent({
        shareUrl: wrongEmail.shareUrl,
        confirmAccess: () => true,
        dependencies: wrongEmail.dependencies,
      }),
    ).rejects.toThrow();

    const expiredCredential = await makeHarness({
      credentialExpiresAt: new Date(Date.now() - 1_000).toISOString(),
    });
    await expect(
      accessSharedContent({
        shareUrl: expiredCredential.shareUrl,
        confirmAccess: () => true,
        dependencies: expiredCredential.dependencies,
      }),
    ).rejects.toThrow();

    const expiredSession = await makeHarness({
      sessionExpiresAt: new Date(Date.now() - 1_000).toISOString(),
    });
    await expect(
      accessSharedContent({
        shareUrl: expiredSession.shareUrl,
        confirmAccess: () => true,
        dependencies: expiredSession.dependencies,
      }),
    ).rejects.toThrow();
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
            envelope: policyContract.envelope,
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
