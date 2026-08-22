import { ed25519 } from "@noble/curves/ed25519";
import { sha256 } from "@noble/hashes/sha256";
import { base58btc } from "multiformats/bases/base58";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { canonicalize } from "@tinycloud/share-envelope";
import { signCompactUcanRootAuthorization } from "@tinycloud/sdk-core";
import { publishAddressedShare, type AddressedOwnerRootInput } from "@tinycloud/share-sdk";
import { CREDENTIAL_INVITATION_REQUEST_DOMAIN, DELIVERY_ADMISSION_DOMAIN } from "../src/protocol.js";
import type { D1DatabaseLike, D1PreparedStatementLike } from "../src/store.js";
import worker, { type EmailEnv } from "../src/worker.js";

const SHARE_ORIGIN = "https://share.tinycloud.xyz";
const API_ORIGIN = "https://api.share.tinycloud.xyz";
const RECIPIENT = "alice@example.com";
const LABEL = "Quarterly report.pdf";
const RESOURCE = "tinycloud:test-space/kv/shares/report.pdf";
const nodeSeed = new Uint8Array(32).fill(7);
const ownerSeed = new Uint8Array(32).fill(6);
const senderSeed = new Uint8Array(32).fill(8);
const did = (seed: Uint8Array): string => `did:key:${base58btc.encode(Uint8Array.from([0xed, 0x01, ...ed25519.getPublicKey(seed)]))}`;
const NODE_DID = did(nodeSeed);
const OWNER_DID = did(ownerSeed);
const SENDER_DID = did(senderSeed);
const b64 = (bytes: Uint8Array): string => Buffer.from(bytes).toString("base64url");
const hex = (bytes: Uint8Array): string => [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");

function attenuation(input: AddressedOwnerRootInput): Record<string, Record<string, readonly unknown[]>> {
  return Object.fromEntries(input.capabilities.map((capability) => capability.kind === "encryption"
    ? [capability.resource, { [capability.action]: [{}] }]
    : [capability.resource, Object.fromEntries(capability.actions.map((action) => [action, [{ type: "xyz.tinycloud.resource/selector", kind: capability.selector, value: capability.resource }]]))]));
}

async function publication(now: number) {
  return publishAddressedShare({
    shareId: "emaildeliveryfixture0001",
    shareOrigin: SHARE_ORIGIN,
    nodeOrigin: "https://owner-node.example",
    nodeAudience: NODE_DID,
    enforcerDid: NODE_DID,
    spaceId: "tinycloud:test-space",
    target: { kind: "email", address: RECIPIENT },
    resource: { kind: "exact", path: "shares/report.pdf" },
    actions: ["read"],
    policyActions: ["tinycloud.kv/get", "tinycloud.kv/metadata"],
    contentSource: {
      shareId: "emaildeliveryfixture0001",
      kvResource: RESOURCE,
      selector: "exact",
      encryptionNetwork: `urn:tinycloud:encryption:${OWNER_DID}:default`,
      encryptedSymmetricKeyDigestHex: "1".repeat(64),
      keyVersion: 1,
      mode: "immutable",
      initialCiphertextDigestHex: "2".repeat(64),
    },
    credentialRequirement: {
      type: "TinyCloudPolicyCredentialRequirement",
      version: 1,
      requirementDigest: "e3awkBcMp_Ff0YBZXI2XUPYyKmkE_HjeAXI7tz6Brgo",
      descriptorDigest: "1tg-qphmKBVtNwzVg9xyz-xxqt_xtMXAsQyXw46m8S0",
      issuerDid: "did:web:issuer.credentials.org",
      issuerKid: "did:web:issuer.credentials.org#controller",
      profile: { id: "tinycloud.email-proof/v1", version: 1 },
      credentialType: { id: "opencredentials.email/v1", version: 1 },
    },
    filename: LABEL,
    mediaType: "application/pdf",
    byteLength: 100,
    deliveryEmail: RECIPIENT,
    expiresAt: new Date(now + 24 * 60 * 60_000),
    authority: {
      ownerDid: OWNER_DID,
      async createOwnerRoot(input) {
        const facts: Record<string, unknown> = {
          ownerDid: input.ownerDid,
          policyId: input.policyId,
          policyDigestHex: input.policyDigestHex,
          policyCid: input.policyCid,
          contentSourceDigestHex: input.contentSourceDigestHex,
          capabilityCeilingHashHex: input.capabilityCeilingHashHex,
          nativeProjectionHashHex: input.nativeProjectionHashHex,
          nodeAudience: input.nodeAudience,
          role: input.role,
          mode: input.role === "policy-authority" ? "policy-source" : "conditional-mint",
          ...(input.role === "policy-enforcement" ? { enforcerDid: NODE_DID } : {}),
        };
        const root = await signCompactUcanRootAuthorization({
          issuerDid: OWNER_DID,
          audienceDid: input.audienceDid,
          attenuation: attenuation(input),
          facts: [facts],
          notBefore: Math.floor(input.notBefore.getTime() / 1000),
          expiresAt: Math.floor(input.expiresAt.getTime() / 1000),
          nonce: `${input.role}-fixture`,
          sign: async (bytes) => ed25519.sign(bytes, ownerSeed),
        });
        return { cid: root.cid, delegationHeader: { Authorization: `Bearer ${root.authorization}` } };
      },
      async sign(bytes) { return ed25519.sign(bytes, ownerSeed); },
      async registerPolicy(input) {
        const issuedAt = new Date(now).toISOString().replace(".000Z", "Z");
        const expiresAt = new Date(now + 24 * 60 * 60_000).toISOString().replace(".000Z", "Z");
        const unsigned = {
          schema: "xyz.tinycloud.policy/attested-enforcer/v2" as const,
          enforcerDid: NODE_DID,
          nodeAudience: NODE_DID,
          attestationBindingDigestHex: hex(sha256(new TextEncoder().encode(canonicalize({ enforcerDid: NODE_DID, nodeAudience: NODE_DID })))),
          issuedAt,
          expiresAt,
        };
        const digest = sha256(new TextEncoder().encode(`xyz.tinycloud.policy/AttestedEnforcerBinding/v2\0${canonicalize(unsigned)}`));
        return {
          policyCid: input.policyCid,
          policyRootCid: input.policyRoot.cid,
          enforcementRootCid: input.enforcementRoot.cid,
          attestedEnforcerBinding: { ...unsigned, signature: { suite: "Ed25519" as const, signerDid: NODE_DID, value: b64(ed25519.sign(digest, nodeSeed)) } },
        };
      },
    },
  });
}

async function receipt(overrides: { request?: Record<string, unknown>; admission?: Record<string, unknown>; proof?: Record<string, unknown> } = {}): Promise<Record<string, unknown>> {
  const now = Date.now();
  const published = await publication(now);
  const envelope = published.deliveryMaterial!.envelope as any;
  const request = {
    schema: "xyz.tinycloud.credentials/invitation-request/v1",
    policyId: envelope.policyCid,
    recipient: RECIPIENT,
    resource: RESOURCE,
    credentialType: "opencredentials.email/v1",
    returnLink: published.url,
    envelopeRef: published.link.cid,
    label: LABEL,
    shareExpiresAt: envelope.expiry,
    audience: API_ORIGIN,
    issuedAt: new Date(now).toISOString(),
    expiresAt: new Date(now + 4 * 60_000).toISOString(),
    nonce: b64(new Uint8Array(16).fill(3)),
    ...overrides.request,
  };
  const unsignedAdmission = {
    ...request,
    schema: "xyz.tinycloud.policy/delivery-admission/v0",
    ownerDid: OWNER_DID,
    actions: ["tinycloud.kv/get"],
    senderKeyDid: SENDER_DID,
    ...overrides.admission,
  };
  const nodeDigest = sha256(new TextEncoder().encode(`${DELIVERY_ADMISSION_DOMAIN}${canonicalize(unsignedAdmission)}`));
  const admission = { ...unsignedAdmission, signature: { suite: "eddsa-ed25519-sha256-jcs-v1", signerDid: NODE_DID, value: b64(ed25519.sign(nodeDigest, nodeSeed)) } };
  const senderDigest = sha256(new TextEncoder().encode(`${CREDENTIAL_INVITATION_REQUEST_DOMAIN}${canonicalize(request)}`));
  const proof = { alg: "EdDSA", kid: SENDER_DID, signature: b64(ed25519.sign(senderDigest, senderSeed)), ...overrides.proof };
  return { request, admission, proof };
}

interface Row { idempotency_key: string; share_cid: string; recipient_digest: string; status: string; provider_message_id: string | null; created_at: string; updated_at: string }

function database(): D1DatabaseLike & { rows: Map<string, Row> } {
  const rows = new Map<string, Row>();
  return {
    rows,
    prepare(query: string): D1PreparedStatementLike {
      let args: unknown[] = [];
      const statement: D1PreparedStatementLike = {
        bind(...values: unknown[]) { args = values; return statement; },
        async first<T>() {
          if (query.startsWith("INSERT")) {
            const key = String(args[0]);
            if (rows.has(key)) return null;
            const row = { idempotency_key: key, share_cid: String(args[1]), recipient_digest: String(args[2]), status: "pending", provider_message_id: null, created_at: String(args[3]), updated_at: String(args[3]) };
            rows.set(key, row); return { idempotency_key: key } as T;
          }
          return (rows.get(String(args[0])) ?? null) as T | null;
        },
        async run() {
          const row = rows.get(String(args[0]));
          if (row !== undefined && row.status === "pending") { row.status = String(args[1]); row.provider_message_id = args[2] === null ? null : String(args[2]); row.updated_at = String(args[3]); }
          return undefined;
        },
      };
      return statement;
    },
  };
}

function environment(): EmailEnv & { DELIVERIES: ReturnType<typeof database> } {
  return {
    DELIVERIES: database(),
    RESEND_API_KEY: "re_test",
    EMAIL_FROM: "TinyCloud Share <invite@share.tinycloud.xyz>",
    DELIVERY_AUDIENCE: API_ORIGIN,
    SHARE_ORIGIN,
    RESEND_ENDPOINT: "https://resend.test/emails",
  };
}

const post = (body: unknown): Request => new Request(`${API_ORIGIN}/v1/email`, { method: "POST", headers: { "content-type": "application/json", origin: SHARE_ORIGIN }, body: JSON.stringify(body) });

let provider: ReturnType<typeof vi.fn>;
beforeEach(() => { provider = vi.fn(async () => new Response(JSON.stringify({ id: "msg_1" }), { status: 200 })); vi.stubGlobal("fetch", provider); });
afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks(); });

describe("api.share email-only worker", () => {
  it("sends one exact Node-and-sender-authorized TinyCloud link", async () => {
    const env = environment();
    const body = await receipt();
    const serialized = JSON.stringify(body);
    expect(serialized).not.toContain("envelopeKey");
    expect(serialized).not.toContain("sealedEnvelope");
    expect(serialized).not.toContain("#tc2");
    const response = await worker.fetch(post(body), env);
    expect(response.status).toBe(202);
    expect(provider).toHaveBeenCalledTimes(1);
    const sent = JSON.parse(String((provider.mock.calls[0] as [string, RequestInit])[1].body));
    expect(sent.to).toEqual([RECIPIENT]);
    expect(sent.subject).toContain("Quarterly report.pdf");
    expect(String(sent.text)).toContain(`${SHARE_ORIGIN}/viewer?tc2=`);
    expect(String(sent.text)).not.toContain("#");
    expect([...env.DELIVERIES.rows.values()][0]).toMatchObject({ share_cid: (body.request as any).envelopeRef, status: "sent" });
  });

  it("refuses a replay before a second provider call", async () => {
    const env = environment(); const body = await receipt();
    expect((await worker.fetch(post(body), env)).status).toBe(202);
    expect((await worker.fetch(post(body), env)).status).toBe(200);
    expect(provider).toHaveBeenCalledTimes(1);
  });

  it.each([
    ["recipient", "recipient", "mallory@example.com"],
    ["label", "label", "Other.pdf"],
  ] as const)("refuses a post-authorization substitution: %s", async (_label, field, replacement) => {
    const body = await receipt();
    (body.request as unknown as Record<string, unknown>)[field] = replacement;
    const response = await worker.fetch(post(body), environment());
    expect(response.status).toBe(401);
    expect(provider).not.toHaveBeenCalled();
  });

  it.each([
    ["audience", { request: { audience: "https://other.example" } }],
    ["delegated recipient", { request: { recipient: "mallory@example.com" } }],
    ["delegated label", { request: { label: "Different.pdf" } }],
    ["link", { request: { returnLink: `${SHARE_ORIGIN}/viewer?tc2=bad` } }],
  ])("refuses an unauthorized signed request: %s", async (_label, overrides) => {
    const response = await worker.fetch(post(await receipt(overrides)), environment());
    expect([400, 401]).toContain(response.status);
    expect(provider).not.toHaveBeenCalled();
  });

  it("refuses a forged Node admission and a forged sender proof", async () => {
    const forgedNode = await receipt();
    const nodeSignature = String((forgedNode.admission as any).signature.value);
    (forgedNode.admission as any).signature.value = `${nodeSignature.startsWith("A") ? "B" : "A"}${nodeSignature.slice(1)}`;
    expect((await worker.fetch(post(forgedNode), environment())).status).toBe(401);
    const forgedSender = await receipt();
    const senderSignature = String((forgedSender.proof as any).signature);
    (forgedSender.proof as any).signature = `${senderSignature.startsWith("A") ? "B" : "A"}${senderSignature.slice(1)}`;
    expect((await worker.fetch(post(forgedSender), environment())).status).toBe(401);
    expect(provider).not.toHaveBeenCalled();
  });

  it("exposes no content, blob, policy, binding, registry, or proxy route", async () => {
    const env = environment();
    for (const path of ["/", "/blobs", "/registry", "/bindings", "/policy", "/proxy", "/content", "/share/v3"]) {
      expect((await worker.fetch(new Request(`${API_ORIGIN}${path}`), env)).status).toBe(404);
    }
  });

  it("allows only the Share browser origin while the signatures remain the authority", async () => {
    const request = post(await receipt());
    const response = await worker.fetch(new Request(request, { headers: { "content-type": "application/json", origin: "https://evil.example" } }), environment());
    expect(response.status).toBe(403);
    expect(response.headers.get("access-control-allow-origin")).toBe(SHARE_ORIGIN);
    expect(provider).not.toHaveBeenCalled();
  });
});
