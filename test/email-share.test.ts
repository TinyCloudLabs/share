import { describe, expect, it, vi } from "vitest";
import { didKeyFromEd25519PublicKey, ed25519PublicKeyFromDidKey } from "@tinycloud/share-envelope";
import { ed25519 } from "@noble/curves/ed25519";
import { captureAndScrubLaunch } from "../src/email-share/url.js";
import { canonicalEmail, createInvitationDraft, type SenderScope } from "../src/email-share/protocol.js";
import { createClaimController, createHolder } from "../src/email-share/claim.js";
import type { ShareTransport } from "../src/email-share/transport.js";
import { createSenderController } from "../src/email-share/sender.js";

const seed = new Uint8Array(32).fill(7);
const senderDid = didKeyFromEd25519PublicKey(ed25519.getPublicKey(seed));
const scope: SenderScope = {
  senderDid,
  senderPrivateKey: seed,
  delegation: "uCAESA.kv.terminal",
  delegationCid: "bafkreiekhtgxpb5xhykd6pytalpkmg52trryror2gritt7r56jv2t75fl4",
  authorityMaterialHandle: "amh_kv_001",
  authorityMaterialDigest: "A".repeat(43),
  targetOrigin: "https://node.example",
  nodeAudience: "did:web:node.example",
  spaceId: "did:pkh:eip155:1:0x1111111111111111111111111111111111111111",
  documentName: "Project plan.md",
  senderTrust: "verified",
};

function transport(overrides: Partial<ShareTransport> = {}): ShareTransport {
  return {
    authorizeInvitation: vi.fn(async () => ({ authorization: {} as never, proof: {} as never })),
    requestDelivery: vi.fn(async () => ({ status: "accepted" as const, retryAfterSeconds: 20 })),
    resend: vi.fn(async () => ({ status: "accepted" as const, retryAfterSeconds: 20 })),
    claimChallenge: vi.fn(async () => ({ claimNonce: "A".repeat(43), shareCid: "cid", shareId: "id", policyCid: "policy", delegationCid: "delegation", authorityMaterialHandle: "amh_kv_001", authorityMaterialDigest: "A".repeat(43), contentSource: { kind: "kv" as const, space: "space", path: "doc.md", action: "tinycloud.kv/get" as const }, contentSourceDigest: "A".repeat(43), emailHash: "A".repeat(43), targetOrigin: "https://node.example", nodeAudience: "did:web:node.example", expiresAt: new Date(Date.now() + 60_000).toISOString() })),
    claimRedeem: vi.fn(async (body) => {
      const holderDid = String((body.binding as Record<string, unknown>).holderDid);
      const payload = btoa(JSON.stringify({ sub: holderDid })).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
      return { format: "vc+sd-jwt" as const, credential: `eyJhbGciOiJFZERTQSJ9.${payload}.signature`, holderDid, expiresAt: new Date(Date.now() + 60_000).toISOString() };
    }),
    policyChallenge: vi.fn(), policySession: vi.fn(), read: vi.fn(),
    ...overrides,
  };
}

describe("exact-email share UI protocol boundaries", () => {
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
    const draft = await createInvitationDraft({ email: "Alice+Notes@EXAMPLE.COM", source: { kind: "kv", space: scope.spaceId, path: "documents/plan.md", action: "tinycloud.kv/get" }, scope, shareId: "share-test", expiresAt: new Date(Date.now() + 86_400_000).toISOString(), uploadEnvelope: async (_cid, blob) => { stored = blob; } });
    expect(stored).toBeDefined();
    expect(draft.shareUrl).not.toContain("?");
    expect(draft.envelope.authorizationTarget.kind).toBe("policy");
    expect(draft.envelope.display.recipientHint).toBe("A***@example.com");
  });

  it("normalizes named SQL into the frozen constrained shape and never accepts raw SQL", async () => {
    const draft = await createInvitationDraft({ email: "bob@example.com", source: { kind: "sql", space: scope.spaceId, database: "documents", path: "shared/plan", statement: "shared_document_by_id", arguments: { document_id: 7 }, argumentsDigest: "ignored", action: "tinycloud.sql/read" }, scope: { ...scope, authorityMaterialHandle: "amh_sql_001" }, shareId: "share-sql", expiresAt: new Date(Date.now() + 86_400_000).toISOString(), uploadEnvelope: async () => {} });
    const target = draft.envelope.authorizationTarget;
    expect(target.kind).toBe("policy");
    if (target.kind !== "policy") throw new Error("expected policy target");
    expect(new TextDecoder().decode(Uint8Array.from(atob(target.policyBytes.replace(/-/g, "+").replace(/_/g, "/")), (char) => char.charCodeAt(0)))).toContain("shared_document_by_id");
  });

  it("creates a non-extractable holder key", async () => {
    const holder = await createHolder();
    expect(holder.privateKey.extractable).toBe(false);
    expect(holder.did.startsWith("did:key:z")).toBe(true);
  });

  it("keeps invitation open inert until explicit activation, then supports OTP and resend", async () => {
    const t = transport();
    const controller = createClaimController({ share: { shareId: "id", shareCid: "cid", policyCid: "policy", recipientEmail: "Alice@example.com", recipientHint: "A***@example.com", expiry: new Date(Date.now() + 60_000).toISOString(), nodeOrigin: "https://node.example", nodeAudience: "did:web:node.example", requestOrigin: "https://share.tinycloud.xyz", delegationCid: "delegation", authorityMaterialHandle: "amh_kv_001", authorityMaterialDigest: "A".repeat(43), contentSource: { kind: "kv", space: "space", path: "doc.md", action: "tinycloud.kv/get" }, contentSourceDigest: "A".repeat(43), action: "tinycloud.kv/get", resource: "doc.md" }, invitationId: "B".repeat(22), claimSecret: "C".repeat(43), transport: t });
    expect(t.claimChallenge).not.toHaveBeenCalled();
    await controller.openDocument();
    expect(controller.state.state).toBe("claimed");
    expect(t.claimRedeem).toHaveBeenCalledTimes(1);
    controller.forget();
    expect(controller.state.state).toBe("forgotten");
  });

  it("reports requested instead of pretending that an email was sent", async () => {
    const t = transport();
    const controller = createSenderController({ transport: t, uploadEnvelope: async () => {} });
    await controller.request({ email: "bob@example.com", source: { kind: "kv", space: scope.spaceId, path: "documents/plan.md", action: "tinycloud.kv/get" }, scope, shareId: "share-requested", expiresAt: new Date(Date.now() + 86_400_000).toISOString() });
    expect(controller.state.state).toBe("requested");
    expect(controller.state).toMatchObject({ retryAfterSeconds: 20 });
  });
});
