import { describe, expect, it } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";
import { didKeyFromEd25519PublicKey, type ShareEnvelopeV3 } from "@tinycloud/share-envelope";
import { validateSharePublicConfig } from "../src/email-share/config.js";
import {
  AccountlessReceiverError,
  openAccountlessShare,
} from "../src/viewer/accountless-receiver.js";

const GRANT_ISSUER_DID = didKeyFromEd25519PublicKey(
  ed25519.getPublicKey(new Uint8Array(32).fill(6)),
);
const NODE_ORIGIN = "https://node.tinycloud.xyz";
const ENGINE_ORIGIN = "https://policy.tinycloud.xyz";
const CREDENTIALS_ORIGIN = "https://witness.credentials.org";
const SPACE_ID = "did:pkh:eip155:1:0xowner:default";
const RESOURCE_PATH = "shares/share-1/body.enc";
const RECIPIENT = "sam@tinycloud.xyz";

function config(withEngine = true) {
  return validateSharePublicConfig({
    version: "tinycloud.share-email-claim/config-v1",
    shareOrigin: "https://share.tinycloud.xyz",
    registryOrigin: "https://registry.tinycloud.xyz",
    nodeOrigin: NODE_ORIGIN,
    credentialsOrigin: CREDENTIALS_ORIGIN,
    ...(withEngine
      ? {
          policyEngineOrigin: ENGINE_ORIGIN,
          policyEngineAudience: "urn:tinycloud:policy-engine:prod",
          policyEngineGrantIssuerDid: GRANT_ISSUER_DID,
        }
      : {}),
    emailOrigin: "https://email.tinycloud.xyz",
    nodeAudience: "did:web:node.tinycloud.xyz",
    nodeEnabled: true,
    issuerDid: "did:web:witness.credentials.org",
    issuerVct: "opencredentials.email/v1",
    issuerEnabled: true,
    nodeInvitationKid: "did:web:node.tinycloud.xyz#invite-1",
    nodeInvitationPublicKey: Buffer.from(new Uint8Array(32).fill(1)).toString("base64url"),
    nodeKeyVersion: 1,
    issuerKeyVersion: 1,
    issuerPublicKey: Buffer.from(new Uint8Array(32).fill(2)).toString("base64url"),
  });
}

/**
 * Only the members the receiver reads. The receiver never re-verifies the
 * envelope — `resolveShare` has already done that — so this is the verified
 * projection it is handed, not an unchecked input.
 */
function envelope(overrides: Record<string, unknown> = {}): ShareEnvelopeV3 {
  return {
    version: 3,
    recipientMatcher: { kind: "exactEmail", value: RECIPIENT },
    actions: ["read"],
    resource: { kind: "exact", path: RESOURCE_PATH },
    target: { origin: NODE_ORIGIN, nodeAudience: "did:key:z6Mkenforcer", spaceId: SPACE_ID },
    contentSource: { selector: "exact", kvResource: `${SPACE_ID}/kv/${RESOURCE_PATH}` },
    metadata: { mediaType: "text/markdown" },
    policyEngine: {
      endpoint: ENGINE_ORIGIN,
      audience: "urn:tinycloud:policy-engine:prod",
      grantIssuerDid: GRANT_ISSUER_DID,
      policyId: `pol_${"a".repeat(52)}`,
      requirementId: "recipient-email",
    },
    localContent: {
      keyWrap: "share-envelope-aes-gcm-v1",
      wrappedKey: Buffer.from(new Uint8Array(61).fill(4)).toString("base64url"),
      ciphertextDigest: Buffer.from(new Uint8Array(32).fill(5)).toString("base64url"),
    },
    ...overrides,
  } as unknown as ShareEnvelopeV3;
}

function input(overrides: Record<string, unknown> = {}) {
  return {
    envelope: envelope(),
    shareCid: "bafkreiaaaa",
    config: config(),
    envelopeKey: new Uint8Array(32).fill(9),
    invoke: () => ({ Authorization: "invocation" }),
    openerOrigin: "https://share.tinycloud.xyz",
    ...overrides,
  } as Parameters<typeof openAccountlessShare>[0];
}

function refusal(overrides: Record<string, unknown>): AccountlessReceiverError {
  try {
    openAccountlessShare(input(overrides));
  } catch (error) {
    return error as AccountlessReceiverError;
  }
  throw new Error("expected the receiver to refuse");
}

describe("accountless receiver", () => {
  it("mints a fresh tab-scoped holder key and reads the recipient off the signed envelope", () => {
    const first = openAccountlessShare(input());
    const second = openAccountlessShare(input());

    expect(first.recipientEmail).toBe(RECIPIENT);
    expect(first.holder.did).toMatch(/^did:key:z6Mk/);
    // A new key per open: closing the tab must end access, so two sessions can
    // never share a holder.
    expect(second.holder.did).not.toBe(first.holder.did);
  });

  it("refuses a share whose envelope names no Policy Engine", () => {
    const error = refusal({ envelope: envelope({ policyEngine: undefined }) });
    expect(error.code).toBe("ENGINE_NOT_ENROLLED");
  });

  it("refuses when the deployment has no Policy Engine enrolled", () => {
    const error = refusal({ config: config(false) });
    expect(error.code).toBe("ENGINE_NOT_ENROLLED");
  });

  it("refuses an engine the deployment does not trust, even though the owner signed it", () => {
    for (const substitution of [
      { endpoint: "https://attacker.example.com" },
      { audience: "urn:tinycloud:policy-engine:other" },
      { grantIssuerDid: didKeyFromEd25519PublicKey(ed25519.getPublicKey(new Uint8Array(32).fill(7))) },
    ]) {
      const error = refusal({
        envelope: envelope({
          policyEngine: { ...envelope().policyEngine, ...substitution },
        }),
      });
      expect(error.code).toBe("ENGINE_NOT_ENROLLED");
    }
  });

  it("refuses anything wider than one exact read addressed to one recipient", () => {
    for (const wider of [
      { recipientMatcher: { kind: "emailDomain", value: "tinycloud.xyz" } },
      { resource: { kind: "prefix", path: "shares/" } },
      { actions: ["read", "edit"] },
      { contentSource: { selector: "prefix", kvResource: `${SPACE_ID}/kv/${RESOURCE_PATH}` } },
      { contentSource: { selector: "exact", kvResource: `${SPACE_ID}/kv/other` } },
    ]) {
      const error = refusal({ envelope: envelope(wider) });
      expect(error.code).toBe("UNSUPPORTED_SHARE");
    }
  });

  it("cannot read before a code has been requested", async () => {
    const session = openAccountlessShare(input());
    await expect(session.submitCode("246810")).rejects.toMatchObject({
      name: "AccountlessReceiverError",
      code: "READ_FAILED",
    });
  });

  it("pins egress to the credentials issuer, the node, and the engine — and never a /share/* path", async () => {
    const attempted: string[] = [];
    const session = openAccountlessShare(
      input({
        transport: {
          async request(request: { method: string; url: string }) {
            attempted.push(`${request.method} ${new URL(request.url).origin}${new URL(request.url).pathname}`);
            throw new Error("transport stops the flow after recording the egress");
          },
        },
      }),
    );
    await session.requestCode().catch(() => undefined);

    expect(attempted.length).toBeGreaterThan(0);
    for (const entry of attempted) {
      expect(entry.startsWith(`POST ${CREDENTIALS_ORIGIN}`)).toBe(true);
      expect(entry).not.toContain("/share/");
    }
  });
});
