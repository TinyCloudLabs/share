import { describe, expect, it } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";
import { didKeyFromEd25519PublicKey } from "@tinycloud/share-envelope";
import { verifySignedObject } from "@tinycloud/sdk-core/policy";
import {
  RECIPIENT_EMAIL_REQUIREMENT_ID,
  publishSharePolicyToEngine,
} from "../src/share/policy-engine-publish.js";

const OWNER_SEED = new Uint8Array(32).fill(0x27);
const OWNER_DID = didKeyFromEd25519PublicKey(ed25519.getPublicKey(OWNER_SEED));
const GRANT_ISSUER_DID = didKeyFromEd25519PublicKey(
  ed25519.getPublicKey(new Uint8Array(32).fill(0x5a)),
);
const ENGINE = {
  endpoint: "https://policy.tinycloud.xyz",
  audience: "urn:tinycloud:policy-engine:prod",
  grantIssuerDid: GRANT_ISSUER_DID,
};
const SPACE = "tinycloud:did:pkh:eip155:1:0xowner:default";
const RESOURCE_PATH = "shares/share-1/body.enc";

function recordingTransport(status = 200) {
  const posted: Array<{ url: string; body: unknown }> = [];
  return {
    posted,
    transport: {
      async request(request: { method: string; url: string; body?: unknown }) {
        posted.push({ url: request.url, body: request.body });
        const signedObjects = (request.body as { signedObjects: Array<Record<string, unknown>> }).signedObjects;
        const policy = signedObjects.find((object) => object.schema === "xyz.tinycloud.policy/policy/v0");
        return {
          status,
          finalUrl: request.url,
          body:
            status === 200
              ? { registeredPolicyIds: [policy?.policyId] }
              : { error: { code: "policy_engine_record.grant_issuer_authority", message: "" } },
        };
      },
    },
  };
}

async function publish(transport: { request: (request: { method: string; url: string; body?: unknown }) => Promise<unknown> }) {
  return await publishSharePolicyToEngine({
    engine: ENGINE,
    ownerDid: OWNER_DID,
    sign: async (bytes) => ed25519.sign(bytes, OWNER_SEED),
    recipientEmail: "sam@tinycloud.xyz",
    kvResource: `${SPACE}/kv/${RESOURCE_PATH}`,
    capabilitySpace: SPACE,
    resourcePath: RESOURCE_PATH,
    shareId: "share-1",
    createdAt: "2026-08-19T12:00:00Z",
    expiresAt: "2026-08-20T12:00:00Z",
    transport: transport as never,
  });
}

describe("publishing the share policy to the standalone Policy Engine", () => {
  it("posts one owner-signed authority bundle to the engine's registration route", async () => {
    const { posted, transport } = recordingTransport();
    const result = await publish(transport);

    expect(posted).toHaveLength(1);
    expect(posted[0]!.url).toBe(`${ENGINE.endpoint}/policy/v0/signed-objects`);
    const objects = (posted[0]!.body as { signedObjects: Array<Record<string, unknown>> }).signedObjects;
    expect(objects.map((object) => object.schema)).toEqual([
      "xyz.tinycloud.auth/key-authorization/v0",
      "xyz.tinycloud.policy/engine-record/v0",
      "xyz.tinycloud.policy/policy/v0",
    ]);
    expect(result.policyId).toMatch(/^pol_[a-z2-7]{52}$/);
    expect(result.requirementId).toBe(RECIPIENT_EMAIL_REQUIREMENT_ID);

    // Every object must verify under the engine's own signed-object profile —
    // signature, digest domain, and content-addressed id.
    for (const object of objects) {
      await expect(verifySignedObject(object)).resolves.toBeTruthy();
    }
  });

  it("authorizes exactly one exact resource, read-only, and only this engine's grant issuer", async () => {
    const { posted, transport } = recordingTransport();
    await publish(transport);
    const objects = (posted[0]!.body as { signedObjects: Array<Record<string, unknown>> }).signedObjects;
    const [authorization, record, policy] = objects as [
      Record<string, unknown>,
      Record<string, unknown>,
      Record<string, unknown>,
    ];

    expect(authorization.ownerDid).toBe(OWNER_DID);
    expect(authorization.keyDid).toBe(GRANT_ISSUER_DID);
    expect(authorization.roles).toEqual(["grant-issuer"]);
    // A stale authority must never outlive the share it was published for.
    expect(authorization.expiresAt).toBe("2026-08-20T12:00:00Z");

    expect(record.audience).toBe(ENGINE.audience);
    expect(record.grantIssuerDid).toBe(GRANT_ISSUER_DID);
    expect(record.endpoint).toBe(ENGINE.endpoint);

    expect(policy.ownerDid).toBe(OWNER_DID);
    expect(policy.signingKeyDid).toBe(OWNER_DID);
    expect((policy.resource as { permissionsCeiling: unknown[] }).permissionsCeiling).toEqual([
      { service: "tinycloud.kv", space: SPACE, path: RESOURCE_PATH, actions: ["tinycloud.kv/get"] },
    ]);
    expect(policy.grant).toEqual({
      output: "portable-delegation",
      maxTtlSeconds: 300,
      delegationMode: "terminal",
      revocation: "refresh_only",
    });
  });

  it("gates on the exact recipient inside the still-mandatory domain gate", async () => {
    const { posted, transport } = recordingTransport();
    await publish(transport);
    const objects = (posted[0]!.body as { signedObjects: Array<Record<string, unknown>> }).signedObjects;
    const policy = objects[2]!;
    const evidence = (policy.when as { evidence: Record<string, unknown> }).evidence;

    expect(evidence.requirementId).toBe(RECIPIENT_EMAIL_REQUIREMENT_ID);
    expect(evidence.verifier).toBe("w3c.vc/credential/v1");
    expect(evidence.requirements).toEqual({
      type: "opencredentials.email/v1",
      emailDomains: ["tinycloud.xyz"],
      emails: ["sam@tinycloud.xyz"],
    });
    // No subject atom: the recipient's key is ephemeral and does not exist yet.
    expect(Object.keys(policy.when as object)).toEqual(["evidence"]);
  });

  it("surfaces an engine refusal rather than reporting a published policy", async () => {
    const { transport } = recordingTransport(403);
    await expect(publish(transport)).rejects.toMatchObject({
      name: "PolicyAccessError",
      code: "engine-denied",
      denialCode: "policy_engine_record.grant_issuer_authority",
    });
  });
});
