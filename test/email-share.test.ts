import { describe, expect, it, vi } from "vitest";
import { canonicalize, computeCid, didKeyFromEd25519PublicKey, ed25519PublicKeyFromDidKey, fromBase64Url, toBase64Url } from "@tinycloud/share-envelope";
import { ed25519 } from "@noble/curves/ed25519";
import { captureAndScrubLaunch } from "../src/email-share/url.js";
import { canonicalDigest, canonicalEmail, createInvitationDraft, signedInvitationProof, type AuthoritativePolicyMaterial, type ContentSource, type SenderScope } from "../src/email-share/protocol.js";
import { createClaimController, createHolder } from "../src/email-share/claim.js";
import { readClaimedShare } from "../src/email-share/node-client.js";
import { createHttpTransport, ShareTransportError, type ReadResponse, type ShareTransport } from "../src/email-share/transport.js";
import { createSenderController } from "../src/email-share/sender.js";
import type { ShareLinkPolicy } from "../packages/share-sdk/src/index.js";
import { createHash } from "node:crypto";
import { assertCommonNodeBinding, assertNodeTime, assertReadResponseBinding, verifyNodeProof } from "../src/email-share/node-verifier.js";
import { SIGNATURE_DOMAINS } from "../src/email-share/protocol.js";
import { mountUnavailableSender } from "../src/email-share/view.js";
import { parseCapabilityList } from "../src/share/capability-list.js";

const seed = new Uint8Array(32).fill(7);
const senderDid = didKeyFromEd25519PublicKey(ed25519.getPublicKey(seed));
const issuerSeed = new Uint8Array(32).fill(8);
const issuerDid = didKeyFromEd25519PublicKey(ed25519.getPublicKey(issuerSeed));
const nodeSeed = new Uint8Array(32).fill(2);
const nodeEnforcerDid = didKeyFromEd25519PublicKey(ed25519.getPublicKey(nodeSeed));
const senderSigner = {
  publicKey: ed25519.getPublicKey(seed),
  sign: async (input: { purpose: "envelope" | "inviteAuthorization"; message: string; binding: Record<string, unknown> }): Promise<Uint8Array> => {
    const domain = input.purpose === "envelope" ? SIGNATURE_DOMAINS.envelope : SIGNATURE_DOMAINS.inviteAuthorization;
    return ed25519.sign(new TextEncoder().encode(`${domain}${input.message}`), seed);
  },
};
const scope: SenderScope = {
  policyOwnerDid: "did:pkh:eip155:1:0x2222222222222222222222222222222222222222",
  senderDid,
  signingCapability: { capabilityId: "A".repeat(22), publicKey: ed25519.getPublicKey(seed) },
  signer: senderSigner,
  shareOrigin: "https://share.tinycloud.xyz",
  delegation: "uCAESA.kv.terminal",
  delegationCid: "bafkreiekhtgxpb5xhykd6pytalpkmg52trryror2gritt7r56jv2t75fl4",
  authorityMaterialHandle: "amh_kv_001",
  authorityMaterialDigest: "A".repeat(43),
  targetOrigin: "https://node.example",
  nodeAudience: "did:web:node.example",
  spaceId: "did:pkh:eip155:1:0x1111111111111111111111111111111111111111",
  documentName: "Project plan.md",
  senderTrust: "verified",
  trustedNode: { targetOrigin: "https://node.example", nodeAudience: "did:web:node.example", invitationKid: "did:web:node.example#invitation-key-1", invitationPublicKey: ed25519.getPublicKey(nodeSeed), keyVersion: 1, enabled: true },
  authorityMaterial: {},
};

async function draftPolicy(email: string, source: ContentSource, expiresAt: string): Promise<AuthoritativePolicyMaterial> {
  const policy = { type: "TinyCloudSharePolicy", version: 1, issuerDid: senderDid, recipientEmail: canonicalEmail(email), contentSource: source, contentSourceDigest: await canonicalDigest(source), action: source.action, resource: source.path, expiresAt };
  const bytes = new TextEncoder().encode(canonicalize(policy));
  return { policyCid: await computeCid(bytes), policyBytes: toBase64Url(bytes), policyDigest: await canonicalDigest(policy), policyAuthorityCid: "A".repeat(59), policyAuthorityBytes: "AQ", policyEnforcementCid: "B".repeat(59), policyEnforcementBytes: "Ag" };
}

async function sharePolicy(email: string, source: ContentSource, expiresAt: string): Promise<ShareLinkPolicy> {
  return {
    ...(await draftPolicy(email, source, expiresAt)),
    recipientEmail: canonicalEmail(email),
    source,
    action: source.action,
    resource: source.path,
    expiresAt,
    target: { origin: scope.targetOrigin, nodeAudience: scope.nodeAudience, spaceId: scope.spaceId },
    contentSourceDigest: await canonicalDigest(source),
    delegationCid: scope.delegationCid,
    authorityMaterialDigest: scope.authorityMaterialDigest,
  };
}

function transport(overrides: Partial<ShareTransport> = {}): ShareTransport {
  return {
    authorizeInvitation: vi.fn(async (input) => {
      const request = input.request as Record<string, any>;
      const authorization = { type: "TinyCloudShareInviteAuthorization", version: 1, jti: request.jti, senderDid: request.senderDid, shareCid: request.shareCid, shareId: request.shareId, policyCid: request.policyCid, delegationCid: request.delegationCid, authorityMaterialHandle: request.authorityMaterialHandle, authorityMaterialDigest: request.authorityMaterialDigest, recipientEmail: request.recipientEmail, targetOrigin: request.targetOrigin, nodeAudience: request.nodeAudience, returnOrigin: "https://share.tinycloud.xyz", documentName: request.documentName, senderTrust: request.senderTrust, contentSource: request.contentSource, contentSourceDigest: request.contentSourceDigest, shareExpiresAt: request.shareExpiresAt, issuedAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 300_000).toISOString(), reportAbuseToken: request.reportAbuseToken };
      const bytes = new TextEncoder().encode(`xyz.tinycloud.share/invite-authorization/v1\0${canonicalize(authorization)}`);
      return { authorization: authorization as never, proof: { alg: "EdDSA" as const, kid: "did:web:node.example#invitation-key-1", signature: toBase64Url(ed25519.sign(bytes, nodeSeed)) } };
    }),
    requestDelivery: vi.fn(async () => ({ status: "accepted" as const, retryAfterSeconds: 20, delegationCid: "delegation", authorityMaterialHandle: "amh_kv_001", authorityMaterialDigest: "A".repeat(43) })),
    resend: vi.fn(async () => ({ status: "accepted" as const, retryAfterSeconds: 20, delegationCid: "delegation", authorityMaterialHandle: "amh_kv_001", authorityMaterialDigest: "A".repeat(43) })),
    activate: vi.fn(async () => ({ status: "accepted" as const, retryAfterSeconds: 20, activationId: "A".repeat(22) })),
    claimChallenge: vi.fn(async () => ({ claimNonce: "A".repeat(43), shareCid: "cid", shareId: "id", policyCid: "policy", delegationCid: "delegation", authorityMaterialHandle: "amh_kv_001", authorityMaterialDigest: "A".repeat(43), contentSource: { kind: "kv" as const, space: "space", path: "doc.md", action: "tinycloud.kv/get" as const }, contentSourceDigest: "A".repeat(43), emailHash: "A".repeat(43), targetOrigin: "https://node.example", nodeAudience: "did:web:node.example", expiresAt: new Date(Date.now() + 60_000).toISOString() })),
    claimRedeem: vi.fn(async (body) => {
      const holderDid = String((body.binding as Record<string, unknown>).holderDid);
      const expiresAt = new Date((Math.floor(Date.now() / 1000) + 60) * 1000).toISOString();
      const disclosure = toBase64Url(new TextEncoder().encode(JSON.stringify(["A".repeat(22), "email", "Alice@example.com"])));
      const disclosureDigest = createHash("sha256").update(disclosure).digest("base64url");
      const header = toBase64Url(new TextEncoder().encode(JSON.stringify({ alg: "EdDSA" })));
      const payload = toBase64Url(new TextEncoder().encode(JSON.stringify({ iss: issuerDid, sub: holderDid, iat: Math.floor(Date.now() / 1000), nbf: Math.floor(Date.now() / 1000), exp: Math.floor(Date.parse(expiresAt) / 1000), vct: "opencredentials.email/v1", jti: "test", tinycloud_share: { share_cid: "cid", share_id: "id", policy_cid: "policy", node_audience: "did:web:node.example" }, _sd_alg: "sha-256", _sd: [disclosureDigest] })));
      const signature = toBase64Url(ed25519.sign(new TextEncoder().encode(`${header}.${payload}`), issuerSeed));
      return { format: "vc+sd-jwt" as const, credential: `${header}.${payload}.${signature}~${disclosure}~`, holderDid, expiresAt };
    }),
    policyChallenge: vi.fn(), policySession: vi.fn(), read: vi.fn(),
    ...overrides,
  };
}

describe("exact-email share UI protocol boundaries", () => {
  it("renders the authenticated auth-only state for a valid empty capability list", () => {
    expect(parseCapabilityList({ capabilities: [] })).toEqual([]);
    const root = document.createElement("div");
    mountUnavailableSender(root, "0x1111111111111111111111111111111111111111");
    expect(root.textContent).toContain("OpenKey connected");
    expect(root.textContent).toContain("Sharing is not enabled yet.");
    expect(root.textContent).toContain("Exact-email sharing is unavailable until the trusted node and delivery capability are ready.");
    expect(root.querySelector("button")).toBeNull();
  });

  it.each([
    null,
    {},
    { capabilities: "none" },
    { capabilities: [], extra: true },
  ])("strictly rejects malformed capability list payloads (%j)", (value) => {
    expect(() => parseCapabilityList(value)).toThrow("share capability list is invalid");
  });

  it("scrubs a complete launch synchronously and rejects secret query strings", () => {
    const loc = new URL("https://share.tinycloud.xyz/s/bafkreiekhtgxpb5xhykd6pytalpkmg52trryror2gritt7r56jv2t75fl4#k=" + "A".repeat(43) + "&i=" + "B".repeat(22) + "&c=" + "C".repeat(43));
    const replaceState = vi.fn();
    const launch = captureAndScrubLaunch(loc as unknown as Location, { replaceState } as unknown as History);
    expect(replaceState).toHaveBeenCalledTimes(1);
    expect(launch?.invite?.claimSecret).toBe("C".repeat(43));
    expect(replaceState.mock.calls[0]?.[2]).not.toContain("#");
    const query = new URL(loc); query.search = "?c=" + "C".repeat(43);
    expect(captureAndScrubLaunch(query as unknown as Location, { replaceState: vi.fn() } as unknown as History)).toBeUndefined();
  });

  it("preserves the local-part and lowercases only the domain", () => {
    expect(canonicalEmail("Alice.O+Notes@EXAMPLE.COM")).toBe("Alice.O+Notes@example.com");
    expect(() => canonicalEmail(" Alice@example.com")).toThrow();
    expect(() => canonicalEmail("a..b@example.com")).toThrow();
  });

  it("builds a sealed policy envelope without placing its key in a query", async () => {
    let stored: Uint8Array | undefined;
    const source = { kind: "kv" as const, space: scope.spaceId, path: "documents/plan.md", action: "tinycloud.kv/get" as const };
    const expiresAt = new Date(Date.now() + 86_400_000).toISOString();
    const draft = await createInvitationDraft({ email: "Alice+Notes@EXAMPLE.COM", source, scope, shareId: "share-test", expiresAt, policy: await draftPolicy("Alice+Notes@EXAMPLE.COM", source, expiresAt), uploadEnvelope: async (_cid, blob) => { stored = blob; } });
    expect(stored).toBeDefined();
    expect(draft.shareUrl).not.toContain("?");
    expect(draft.envelope.authorizationTarget.kind).toBe("policy");
    expect(draft.envelope.display.recipientHint).toBe("A***@example.com");
  });

  it("normalizes named SQL into the frozen constrained shape and never accepts raw SQL", async () => {
    const source = { kind: "sql" as const, space: scope.spaceId, database: "documents", path: "shared/plan", statement: "shared_document_by_id", arguments: { document_id: 7 }, argumentsDigest: "ignored", action: "tinycloud.sql/read" as const };
    const sqlScope = { ...scope, authorityMaterialHandle: "amh_sql_001" as const };
    const expiresAt = new Date(Date.now() + 86_400_000).toISOString();
    const draft = await createInvitationDraft({ email: "bob@example.com", source, scope: sqlScope, shareId: "share-sql", expiresAt, policy: await draftPolicy("bob@example.com", source, expiresAt), uploadEnvelope: async () => {} });
    const target = draft.envelope.authorizationTarget;
    expect(target.kind).toBe("policy");
    if (target.kind !== "policy") throw new Error("expected policy target");
    expect(new TextDecoder().decode(Uint8Array.from(atob(target.policyBytes.replace(/-/g, "+").replace(/_/g, "/")), (char) => char.charCodeAt(0)))).toContain("shared_document_by_id");
  });

  it("pins the named-SQL invitation payload to the mounted scope contract", async () => {
    const source = {
      kind: "sql" as const,
      space: scope.spaceId,
      database: "documents",
      path: "shared/plan",
      statement: "shared_document_by_id",
      arguments: { document_id: 123 },
      argumentsDigest: "ignored",
      action: "tinycloud.sql/read" as const,
    };
    const draft = await createInvitationDraft({
      email: "Alice+Notes@example.com",
      source,
      scope: { ...scope, authorityMaterialHandle: "amh_sql_001" },
      shareId: "share-sql-mounted",
      expiresAt: "2026-07-23T12:00:00.000Z",
      now: "2026-07-19T12:00:00.000Z",
      policy: await draftPolicy("Alice+Notes@example.com", source, "2026-07-23T12:00:00.000Z"),
      uploadEnvelope: async () => {},
    });
    const signed = await signedInvitationProof(draft, { ...scope, authorityMaterialHandle: "amh_sql_001" });
    const request = signed.request;
    const expectedSource = {
      kind: "sql",
      space: scope.spaceId,
      database: "documents",
      path: "shared/plan",
      statement: "shared_document_by_id",
      arguments: { document_id: 123 },
      argumentsDigest: "Wvt9ycf107Id2Qe58i0BnWykVBsdjhyS03P2psS0bSg",
      action: "tinycloud.sql/read",
    };
    expect(request.contentSource).toEqual(expectedSource);
    expect(request.contentSourceDigest).toBe("OmF5ZcmUhf6D3372Toi6tvaibZ7kpamg4oFe89d_xwU");
    expect(request.contentSource).toMatchObject({ statement: "shared_document_by_id", argumentsDigest: expectedSource.argumentsDigest, arguments: { document_id: 123 } });
    expect(request).not.toHaveProperty("action");
    expect(request).not.toHaveProperty("resource");
    expect(request.requestBodyDigest).toBe(await canonicalDigest({
      shareCid: request.shareCid,
      shareId: request.shareId,
      policyCid: request.policyCid,
      delegationCid: request.delegationCid,
      authorityMaterialHandle: request.authorityMaterialHandle,
      authorityMaterialDigest: request.authorityMaterialDigest,
      recipientEmail: request.recipientEmail,
      targetOrigin: request.targetOrigin,
      nodeAudience: request.nodeAudience,
      action: "tinycloud.sql/read",
      resource: "shared/plan",
    }));
  });

  it("binds named-SQL reads to the same source and signed markdown body", async () => {
    vi.useFakeTimers();
    vi.setSystemTime("2026-07-19T12:00:00.000Z");
    try {
    const holder = await createHolder();
    const shareExpiry = "2026-07-23T12:00:00.000Z";
    const source = {
      kind: "sql" as const,
      space: scope.spaceId,
      database: "documents",
      path: "shared/plan",
      statement: "shared_document_by_id",
      arguments: { document_id: 123 },
      argumentsDigest: "Wvt9ycf107Id2Qe58i0BnWykVBsdjhyS03P2psS0bSg",
      action: "tinycloud.sql/read" as const,
    };
    const share = {
      shareId: "share-sql-mounted",
      shareCid: "A".repeat(59),
      policyCid: "B".repeat(59),
      recipientEmail: "Alice+Notes@example.com",
      recipientHint: "A***@example.com",
      expiry: shareExpiry,
      nodeOrigin: "https://node.example",
      nodeAudience: "did:web:node.example",
      requestOrigin: "https://share.tinycloud.xyz",
      delegationCid: "C".repeat(59),
      authorityMaterialHandle: "amh_sql_001",
      authorityMaterialDigest: "D".repeat(43),
      contentSource: source,
      contentSourceDigest: "OmF5ZcmUhf6D3372Toi6tvaibZ7kpamg4oFe89d_xwU",
      action: "tinycloud.sql/read" as const,
      resource: "shared/plan",
      trustedNode: scope.trustedNode,
    };
    const credential = "mounted-sql-credential";
    const challenge = (body: Record<string, unknown>) => ({
      ...body,
      type: "TinyCloudSharePolicyChallenge",
      version: 1,
      challengeId: "E".repeat(22),
      nonce: "F".repeat(43),
      enforcerDid: nodeEnforcerDid,
      emailHash: "A".repeat(43),
      issuedAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 119_000).toISOString(),
    });
    const nodeProof = (message: Record<string, unknown>, domain: string) => ({
      alg: "EdDSA" as const,
      kid: share.trustedNode.invitationKid,
      signature: toBase64Url(ed25519.sign(new TextEncoder().encode(domain + canonicalize(message)), nodeSeed)),
    });
    let readRequest: Record<string, unknown> | undefined;
    const t = transport({
      policyChallenge: vi.fn(async (body) => {
        const value = challenge(body as Record<string, unknown>);
        return { challenge: value, proof: nodeProof(value, SIGNATURE_DOMAINS.policyChallenge) };
      }),
      policySession: vi.fn(async (body) => {
        const presentation = body.presentation as Record<string, unknown>;
        expect(Object.keys(presentation).sort()).toEqual([
          "action", "authorityMaterialDigest", "authorityMaterialHandle", "challengeId", "contentSource", "contentSourceDigest",
          "credentialDigest", "delegationCid", "enforcerDid", "expiresAt", "holderDid", "issuedAt", "jti", "nodeAudience",
          "nonce", "policyCid", "requestBodyDigest", "resource", "shareCid", "shareId", "targetOrigin", "type", "version",
        ]);
        expect(presentation.enforcerDid).toBe(nodeEnforcerDid);
        const holderBinding = body.holderBinding as Record<string, unknown>;
        const holderMessage = holderBinding.message as Record<string, unknown>;
        expect(Object.keys(holderMessage).sort()).toEqual([
          "audience", "challengeId", "challengeNonce", "challengeRequestDigest", "claimNonce", "contentSource", "contentSourceDigest",
          "credentialDigest", "emailHash", "enforcerDid", "expiresAt", "holderDid", "invitationId", "issuedAt", "jti", "nodeAudience",
          "policyCid", "redemptionId", "requestOrigin", "shareCid", "shareId", "targetOrigin", "type", "version",
        ]);
        const { challengeId: _challengeId, nonce: _nonce, jti: _jti, requestBodyDigest: _digest, enforcerDid: _enforcerDid, ...sessionFields } = presentation;
        const session = {
          ...sessionFields,
          type: "TinyCloudSharePolicySession",
          version: 1,
          sessionId: "G".repeat(22),
          credentialDigest: createHash("sha256").update(credential).digest("base64url"),
          issuedAt: new Date().toISOString(),
          expiresAt: new Date(Date.now() + 300_000).toISOString(),
        };
        return { session, proof: nodeProof(session, SIGNATURE_DOMAINS.policySession) };
      }),
      read: vi.fn(async (body) => {
        readRequest = body as Record<string, unknown>;
        const invocation = body.invocation as Record<string, unknown>;
        const content = "# SQL mounted plan\n";
        const response: Omit<ReadResponse, "proof"> = {
          type: "TinyCloudShareReadResponse",
          version: 1,
          sessionId: String(invocation.sessionId),
          requestJti: String(invocation.jti),
          readJti: String(invocation.jti),
          audience: share.nodeAudience,
          holderDid: String(invocation.holderDid),
          credentialDigest: createHash("sha256").update(credential).digest("base64url"),
          issuedAt: new Date().toISOString(),
          expiresAt: new Date(Date.now() + 30_000).toISOString(),
          mediaType: "text/markdown; charset=utf-8" as const,
          content,
          contentSource: source,
          contentSourceDigest: share.contentSourceDigest,
          action: "tinycloud.sql/read" as const,
          resource: "shared/plan",
          requestBodyDigest: String(body.requestBodyDigest),
          bodyDigest: createHash("sha256").update(content).digest("base64url"),
          delegationCid: share.delegationCid,
          authorityMaterialHandle: share.authorityMaterialHandle,
          authorityMaterialDigest: share.authorityMaterialDigest,
        };
        return { ...response, proof: nodeProof(response, SIGNATURE_DOMAINS.readResponse) };
      }),
    });
    const content = await readClaimedShare({ share, claim: { holder, credential, expiresAt: share.expiry, persisted: false }, transport: t });
    expect(content).toBe("# SQL mounted plan\n");
    expect(readRequest?.contentSource).toEqual(source);
    expect(readRequest?.contentSourceDigest).toBe(share.contentSourceDigest);
    expect(readRequest?.action).toBe("tinycloud.sql/read");
    expect(readRequest?.resource).toBe("shared/plan");
    const invocation = readRequest?.invocation as Record<string, unknown>;
    expect(invocation.contentSource).toEqual(source);
    expect(invocation.requestBodyDigest).toBe(readRequest?.requestBodyDigest);
    const { requestBodyDigest: _digest, ...invocationWithoutDigest } = invocation;
    expect(readRequest?.requestBodyDigest).toBe(await canonicalDigest({
      sessionId: readRequest?.sessionId,
      delegationCid: readRequest?.delegationCid,
      authorityMaterialHandle: readRequest?.authorityMaterialHandle,
      authorityMaterialDigest: readRequest?.authorityMaterialDigest,
      contentSource: readRequest?.contentSource,
      contentSourceDigest: readRequest?.contentSourceDigest,
      action: readRequest?.action,
      resource: readRequest?.resource,
      invocation: invocationWithoutDigest,
    }));
    } finally {
      vi.useRealTimers();
    }
  });

  it("creates a non-extractable holder key", async () => {
    const holder = await createHolder();
    expect(holder.privateKey.extractable).toBe(false);
    expect(holder.did.startsWith("did:key:z")).toBe(true);
  });

  it("keeps invitation open inert until explicit activation, then supports OTP and resend", async () => {
    const t = transport();
    const states: string[] = [];
    const controller = createClaimController({ share: { shareId: "id", shareCid: "cid", policyCid: "policy", recipientEmail: "Alice@example.com", recipientHint: "A***@example.com", expiry: new Date(Date.now() + 600_000).toISOString(), nodeOrigin: "https://node.example", nodeAudience: "did:web:node.example", requestOrigin: "https://share.tinycloud.xyz", delegationCid: "delegation", authorityMaterialHandle: "amh_kv_001", authorityMaterialDigest: "A".repeat(43), contentSource: { kind: "kv", space: "space", path: "doc.md", action: "tinycloud.kv/get" }, contentSourceDigest: "A".repeat(43), action: "tinycloud.kv/get", resource: "doc.md", trustedNode: { targetOrigin: "https://node.example", nodeAudience: "did:web:node.example", invitationKid: "did:web:node.example#invitation-key-1", invitationPublicKey: ed25519.getPublicKey(nodeSeed), keyVersion: 1, enabled: true } }, invitationId: "B".repeat(22), claimSecret: "C".repeat(43), transport: t, credentialTrust: { issuerDid, vct: "opencredentials.email/v1", issuerPublicKey: ed25519.getPublicKey(issuerSeed) } });
    controller.subscribe((next) => states.push(next.state));
    expect(t.claimChallenge).not.toHaveBeenCalled();
    await controller.openDocument();
    expect(states).toEqual(["activation", "challenge", "redeeming", "claimed"]);
    expect(t.activate).toHaveBeenCalledTimes(1);
    expect(controller.state.state).toBe("claimed");
    expect(t.claimRedeem).toHaveBeenCalledTimes(1);
    controller.forget();
    expect(controller.state.state).toBe("forgotten");
  });

  it("uses a scanner-safe activation POST with the exact claim body", async () => {
    const requests: Array<{ readonly url: string; readonly init: RequestInit }> = [];
    const fetchFn: typeof fetch = async (input, init) => {
      requests.push({ url: String(input), init: init ?? {} });
      return new Response(JSON.stringify({ status: "accepted", retryAfterSeconds: 20, activationId: "A".repeat(22) }), { status: 200, headers: { "content-type": "application/json" } });
    };
    const http = createHttpTransport({ nodeOrigin: "https://node.example", credentialsOrigin: "https://credentials.example", fetchFn });
    await expect(http.activate({ invitationId: "B".repeat(22), claimSecret: "C".repeat(43) })).resolves.toEqual({ status: "accepted", retryAfterSeconds: 20, activationId: "A".repeat(22) });
    expect(requests).toHaveLength(1);
    expect(requests[0]?.url).toBe("https://credentials.example/v1/share-email/claims/activate");
    expect(requests[0]?.init.method).toBe("POST");
    expect(JSON.parse(String(requests[0]?.init.body))).toEqual({ invitationId: "B".repeat(22), claimSecret: "C".repeat(43) });
    expect(requests.some(({ init }) => init.method === "GET")).toBe(false);
  });

  it("keeps OTP fallback, resend cooldown, and terminal claim states explicit", async () => {
    const t = transport({ activate: vi.fn(async () => { throw new ShareTransportError("denied"); }) });
    const controller = createClaimController({ share: { shareId: "id", shareCid: "cid", policyCid: "policy", recipientEmail: "Alice@example.com", recipientHint: "A***@example.com", expiry: new Date(Date.now() + 600_000).toISOString(), nodeOrigin: "https://node.example", nodeAudience: "did:web:node.example", requestOrigin: "https://share.tinycloud.xyz", delegationCid: "delegation", authorityMaterialHandle: "amh_kv_001", authorityMaterialDigest: "A".repeat(43), contentSource: { kind: "kv", space: "space", path: "doc.md", action: "tinycloud.kv/get" }, contentSourceDigest: "A".repeat(43), action: "tinycloud.kv/get", resource: "doc.md", trustedNode: { targetOrigin: "https://node.example", nodeAudience: "did:web:node.example", invitationKid: "did:web:node.example#invitation-key-1", invitationPublicKey: ed25519.getPublicKey(nodeSeed), keyVersion: 1, enabled: true } }, invitationId: "B".repeat(22), claimSecret: "C".repeat(43), transport: t, credentialTrust: { issuerDid, vct: "opencredentials.email/v1", issuerPublicKey: ed25519.getPublicKey(issuerSeed) } });
    await controller.openDocument();
    expect(controller.state.state).toBe("otp");
    vi.useFakeTimers();
    await controller.resend();
    expect(controller.state.state).toBe("otp");
    expect(controller.state).toMatchObject({ retryAfterSeconds: 20 });
    vi.advanceTimersByTime(20_000);
    expect(controller.state).toMatchObject({ state: "otp", retryAfterSeconds: 0 });
    vi.useRealTimers();
    await controller.resend();
    expect(t.resend).toHaveBeenCalledTimes(1);
    await controller.submitOtp("042731");
    expect(controller.state.state).toBe("claimed");

    for (const code of ["used", "expired", "revoked"] as const) {
      const failed = transport({ activate: vi.fn(async () => { throw new ShareTransportError(code); }) });
      const terminal = createClaimController({ share: { shareId: "id", shareCid: "cid", policyCid: "policy", recipientEmail: "Alice@example.com", recipientHint: "A***@example.com", expiry: new Date(Date.now() + 600_000).toISOString(), nodeOrigin: "https://node.example", nodeAudience: "did:web:node.example", requestOrigin: "https://share.tinycloud.xyz", delegationCid: "delegation", authorityMaterialHandle: "amh_kv_001", authorityMaterialDigest: "A".repeat(43), contentSource: { kind: "kv", space: "space", path: "doc.md", action: "tinycloud.kv/get" }, contentSourceDigest: "A".repeat(43), action: "tinycloud.kv/get", resource: "doc.md", trustedNode: { targetOrigin: "https://node.example", nodeAudience: "did:web:node.example", invitationKid: "did:web:node.example#invitation-key-1", invitationPublicKey: ed25519.getPublicKey(nodeSeed), keyVersion: 1, enabled: true } }, invitationId: "B".repeat(22), claimSecret: "C".repeat(43), transport: failed, credentialTrust: { issuerDid, vct: "opencredentials.email/v1", issuerPublicKey: ed25519.getPublicKey(issuerSeed) } });
      await terminal.openDocument();
      expect(terminal.state.state).toBe(code === "expired" ? "otp" : code);
    }
  });

  it("queues the automatic read until claim completion releases the controller lock", async () => {
    const t = transport();
    const share = { shareId: "id", shareCid: "cid", policyCid: "policy", recipientEmail: "Alice@example.com", recipientHint: "A***@example.com", expiry: new Date(Date.now() + 600_000).toISOString(), nodeOrigin: "https://node.example", nodeAudience: "did:web:node.example", requestOrigin: "https://share.tinycloud.xyz", delegationCid: "delegation", authorityMaterialHandle: "amh_kv_001", authorityMaterialDigest: "A".repeat(43), contentSource: { kind: "kv" as const, space: "space", path: "doc.md", action: "tinycloud.kv/get" as const }, contentSourceDigest: "A".repeat(43), action: "tinycloud.kv/get" as const, resource: "doc.md", trustedNode: { targetOrigin: "https://node.example", nodeAudience: "did:web:node.example", invitationKid: "did:web:node.example#invitation-key-1", invitationPublicKey: ed25519.getPublicKey(nodeSeed), keyVersion: 1, enabled: true as const } };
    const controller = createClaimController({ share, invitationId: "B".repeat(22), claimSecret: "C".repeat(43), transport: t, credentialTrust: { issuerDid, vct: "opencredentials.email/v1", issuerPublicKey: ed25519.getPublicKey(issuerSeed) } });
    let automaticRead: Promise<string | undefined> | undefined;
    controller.subscribe((state) => { if (state.state === "claimed" && automaticRead === undefined) automaticRead = controller.read(); });
    await controller.openDocument();
    await automaticRead;
    expect(t.policyChallenge).toHaveBeenCalledTimes(1);
    expect(controller.state.state).toBe("error");
  });

  it("verifies signed session bindings and read content before entering reading", async () => {
    const t = transport();
    const share = { shareId: "id", shareCid: "cid", policyCid: "policy", recipientEmail: "Alice@example.com", recipientHint: "A***@example.com", expiry: new Date(Date.now() + 600_000).toISOString(), nodeOrigin: "https://node.example", nodeAudience: "did:web:node.example", requestOrigin: "https://share.tinycloud.xyz", delegationCid: "delegation", authorityMaterialHandle: "amh_kv_001", authorityMaterialDigest: "A".repeat(43), contentSource: { kind: "kv" as const, space: "space", path: "doc.md", action: "tinycloud.kv/get" as const }, contentSourceDigest: "A".repeat(43), action: "tinycloud.kv/get" as const, resource: "doc.md", trustedNode: { targetOrigin: "https://node.example", nodeAudience: "did:web:node.example", invitationKid: "did:web:node.example#invitation-key-1", invitationPublicKey: ed25519.getPublicKey(nodeSeed), keyVersion: 1, enabled: true as const } };
    const controller = createClaimController({ share, invitationId: "B".repeat(22), claimSecret: "C".repeat(43), transport: t, credentialTrust: { issuerDid, vct: "opencredentials.email/v1", issuerPublicKey: ed25519.getPublicKey(issuerSeed) } });
    await controller.openDocument();
    if (controller.state.state !== "claimed") throw new Error("claim did not complete");
    const credential = controller.state.claim.credential;
    const outage = vi.fn(async () => { throw new ShareTransportError("offline", true); });
    t.policyChallenge = outage;
    await controller.read();
    expect(controller.state).toMatchObject({ state: "error", code: "offline", retryable: true });
    expect(outage).toHaveBeenCalledTimes(1);
    expect(t.activate).toHaveBeenCalledTimes(1);
    expect(t.claimRedeem).toHaveBeenCalledTimes(1);
    const now = Date.now();
    t.policyChallenge = vi.fn(async (body) => {
      const challenge = { ...body, type: "TinyCloudSharePolicyChallenge", version: 1, challengeId: "D".repeat(43), nonce: "E".repeat(43), enforcerDid: nodeEnforcerDid, emailHash: "A".repeat(43), issuedAt: new Date(now).toISOString(), expiresAt: new Date(now + 60_000).toISOString() };
      return { challenge, proof: { alg: "EdDSA" as const, kid: share.trustedNode.invitationKid, signature: toBase64Url(ed25519.sign(new TextEncoder().encode(`${SIGNATURE_DOMAINS.policyChallenge}${canonicalize(challenge)}`), nodeSeed)) } };
    });
    t.policySession = vi.fn(async (body) => {
      const presentation = body.presentation as Record<string, unknown>;
      const session = { type: "TinyCloudSharePolicySession", version: 1, sessionId: "F".repeat(22), shareCid: presentation.shareCid, shareId: presentation.shareId, delegationCid: presentation.delegationCid, policyCid: presentation.policyCid, authorityMaterialHandle: presentation.authorityMaterialHandle, authorityMaterialDigest: presentation.authorityMaterialDigest, contentSource: presentation.contentSource, contentSourceDigest: presentation.contentSourceDigest, holderDid: presentation.holderDid, targetOrigin: presentation.targetOrigin, nodeAudience: presentation.nodeAudience, action: presentation.action, resource: presentation.resource, credentialDigest: createHash("sha256").update(credential).digest("base64url"), issuedAt: new Date(now).toISOString(), expiresAt: new Date(now + 300_000).toISOString() };
      return { session, proof: { alg: "EdDSA" as const, kid: share.trustedNode.invitationKid, signature: toBase64Url(ed25519.sign(new TextEncoder().encode(`${SIGNATURE_DOMAINS.policySession}${canonicalize(session)}`), nodeSeed)) } };
    });
    t.read = vi.fn(async (body) => {
      const request = body as Record<string, any>;
      const invocation = request.invocation as Record<string, any>;
      const content = "# Verified\n";
      const issuedAt = new Date().toISOString();
      const responseBody = { type: "TinyCloudShareReadResponse", version: 1, sessionId: invocation.sessionId, requestJti: invocation.jti, readJti: invocation.jti, audience: share.nodeAudience, holderDid: invocation.holderDid, credentialDigest: createHash("sha256").update(credential).digest("base64url"), issuedAt, expiresAt: new Date(Date.now() + 30_000).toISOString(), mediaType: "text/markdown; charset=utf-8", content, contentSource: share.contentSource, contentSourceDigest: share.contentSourceDigest, action: share.action, resource: share.resource, requestBodyDigest: request.requestBodyDigest, bodyDigest: createHash("sha256").update(content).digest("base64url"), delegationCid: share.delegationCid, authorityMaterialHandle: share.authorityMaterialHandle, authorityMaterialDigest: share.authorityMaterialDigest };
      const proof = { alg: "EdDSA" as const, kid: share.trustedNode.invitationKid, signature: toBase64Url(ed25519.sign(new TextEncoder().encode(`${SIGNATURE_DOMAINS.readResponse}${canonicalize(responseBody)}`), nodeSeed)) };
      return { ...responseBody, proof } as any;
    });
    await controller.retry();
    expect(controller.state.state).toBe("claimed");
    expect(t.policyChallenge).toHaveBeenCalledTimes(1);
    expect(t.policySession).toHaveBeenCalledTimes(1);
    expect(t.read).toHaveBeenCalledTimes(1);
    const sessionRequest = (t.policySession as unknown as { readonly mock: { readonly calls: readonly (readonly [Record<string, unknown>])[] } }).mock.calls[0]?.[0] as Record<string, unknown>;
    expect(Object.keys(sessionRequest).sort()).toEqual(["credential", "holderBinding", "presentation", "proof", "readSignerDid"]);
    expect(sessionRequest.readSignerDid).toBe((sessionRequest.presentation as Record<string, unknown>).holderDid);
    const artifact = sessionRequest.holderBinding as Record<string, any>;
    expect(artifact).toMatchObject({ name: "holderBinding", domain: SIGNATURE_DOMAINS.holderBinding, signerDid: sessionRequest.readSignerDid });
    expect(Object.keys(artifact).sort()).toEqual(["domain", "jcs", "message", "messageDigest", "name", "signature", "signatureDigest", "signedBytesDigest", "signerDid"]);
    expect(artifact.message).toMatchObject({ redemptionId: "id", invitationId: "cid", claimNonce: "E".repeat(43), challengeNonce: "E".repeat(43), credentialDigest: createHash("sha256").update(credential).digest("base64url"), audience: share.nodeAudience, enforcerDid: nodeEnforcerDid, requestOrigin: share.nodeOrigin, challengeId: "D".repeat(43) });
    expect(artifact.jcs).toBe(canonicalize(artifact.message));
    expect(artifact.messageDigest).toBe(await canonicalDigest(artifact.message));
    expect(artifact.signedBytesDigest).toBe(createHash("sha256").update(`${SIGNATURE_DOMAINS.holderBinding}${artifact.jcs}`).digest("base64url"));
    expect(artifact.signatureDigest).toBe(createHash("sha256").update(fromBase64Url(artifact.signature.value)).digest("base64url"));
  });

  it("rejects forged, stale, and misbound Node responses before UI advancement", async () => {
    const message = { type: "TinyCloudSharePolicyChallenge", version: 1, challengeId: "A".repeat(43), nonce: "B".repeat(43) };
    const proof = { alg: "EdDSA" as const, kid: "did:web:node.example#invitation-key-1", signature: toBase64Url(ed25519.sign(new TextEncoder().encode(`${SIGNATURE_DOMAINS.policyChallenge}${canonicalize(message)}`), nodeSeed)) };
    await expect(verifyNodeProof(message, proof, { targetOrigin: "https://node.example", nodeAudience: "did:web:node.example", invitationKid: proof.kid, invitationPublicKey: ed25519.getPublicKey(nodeSeed), keyVersion: 1, enabled: true }, SIGNATURE_DOMAINS.policyChallenge)).resolves.toBeUndefined();
    await expect(verifyNodeProof(message, { ...proof, signature: `${proof.signature.slice(0, -1)}A` }, { targetOrigin: "https://node.example", nodeAudience: "did:web:node.example", invitationKid: proof.kid, invitationPublicKey: ed25519.getPublicKey(nodeSeed), keyVersion: 1, enabled: true }, SIGNATURE_DOMAINS.policyChallenge)).rejects.toThrow();
    expect(() => assertNodeTime("2020-01-01T00:00:00.000Z", "2020-01-01T00:02:00.000Z", Date.parse("2026-07-19T00:00:00.000Z"), 120)).toThrow();
    const share = { shareId: "id", shareCid: "cid", policyCid: "policy", recipientEmail: "Alice@example.com", recipientHint: "A***@example.com", expiry: "2026-07-23T12:00:00.000Z", nodeOrigin: "https://node.example", nodeAudience: "did:web:node.example", requestOrigin: "https://share.tinycloud.xyz", delegationCid: "delegation", authorityMaterialHandle: "amh_kv_001", authorityMaterialDigest: "A".repeat(43), contentSource: { kind: "kv" as const, space: "space", path: "doc.md", action: "tinycloud.kv/get" as const }, contentSourceDigest: "A".repeat(43), action: "tinycloud.kv/get" as const, resource: "doc.md", trustedNode: { targetOrigin: "https://node.example", nodeAudience: "did:web:node.example", invitationKid: proof.kid, invitationPublicKey: ed25519.getPublicKey(nodeSeed), keyVersion: 1, enabled: true as const } };
    expect(() => assertCommonNodeBinding({ shareCid: "wrong" }, share, "did:key:z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw")).toThrow();
    expect(() => assertReadResponseBinding({ mediaType: "text/markdown; charset=utf-8", content: "# Plan\n", contentSourceDigest: "B".repeat(43), bodyDigest: "C".repeat(43), delegationCid: "delegation", authorityMaterialHandle: "amh_kv_001", authorityMaterialDigest: "A".repeat(43) }, share)).toThrow();
  });

  it("does not report delivery when the mounted policy authority is incomplete", async () => {
    const t = transport();
    const controller = createSenderController({ transport: t, uploadEnvelope: async () => {} });
    const source = { kind: "kv" as const, space: scope.spaceId, path: "documents/plan.md", action: "tinycloud.kv/get" as const };
    const expiresAt = new Date(Date.now() + 86_400_000).toISOString();
    await controller.request({ email: "bob@example.com", source, scope, shareId: "share-requested", expiresAt, policy: await sharePolicy("bob@example.com", source, expiresAt) });
    expect(controller.state.state).toBe("invalid");
  });
});
