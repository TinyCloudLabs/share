import { describe, expect, it } from "vitest";
import { validateSharePublicConfig } from "../src/email-share/config.js";
import {
  policyEngineBindingFromConfig,
  readAccountlessShare,
  receiverOriginPolicy,
} from "../src/email-share/policy-access.js";
import {
  createEphemeralHolderKey,
  requestedCapabilitiesHashHex,
} from "@tinycloud/sdk-core/policy-access";
import { deriveDelegationCid } from "@tinycloud/sdk-core/requester";
import { POLICY_ENGINE_ROUTES, upstreamForPath } from "../src/host/upstream.js";
import { validateTrustBundle } from "../src/host/trust-bundle.js";
import { ed25519 } from "@noble/curves/ed25519";

const GRANT_ISSUER_SEED = new Uint8Array(32).fill(6);
function didKey(publicKey: Uint8Array): string {
  const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  const bytes = Uint8Array.from([0xed, 0x01, ...publicKey]);
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  let out = "";
  while (value > 0n) {
    out = alphabet[Number(value % 58n)] + out;
    value /= 58n;
  }
  return `did:key:z${out}`;
}
const GRANT_ISSUER_DID = didKey(ed25519.getPublicKey(GRANT_ISSUER_SEED));

const NODE_ORIGIN = "https://node.tinycloud.xyz";
const ENGINE_ORIGIN = "https://policy.tinycloud.xyz";
const CREDENTIALS_ORIGIN = "https://witness.credentials.org";
const CAPABILITY_SPACE = "tinycloud:did:pkh:eip155:1:0xowner:default";
const NODE_SPACE_ID = "did:pkh:eip155:1:0xowner:default";
const RESOURCE_PATH = "shares/share-1/body.enc";
const POLICY_ID = "pol_share_exact_email";

function rawConfig(withEngine: boolean): Record<string, unknown> {
  return {
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
    nodeInvitationPublicKey: Buffer.from(new Uint8Array(32).fill(1)).toString(
      "base64url",
    ),
    nodeKeyVersion: 1,
    issuerKeyVersion: 1,
    issuerPublicKey: Buffer.from(new Uint8Array(32).fill(2)).toString(
      "base64url",
    ),
  };
}

function publicConfig(withEngine: boolean) {
  return validateSharePublicConfig(rawConfig(withEngine));
}

describe("share public config policy engine binding", () => {
  it("accepts an enrolled policy engine and exposes it as a binding", () => {
    const binding = policyEngineBindingFromConfig(publicConfig(true));
    expect(binding).toEqual({
      endpoint: ENGINE_ORIGIN,
      audience: "urn:tinycloud:policy-engine:prod",
      grantIssuerDid: GRANT_ISSUER_DID,
    });
  });

  it("reports no binding rather than inventing an endpoint", () => {
    expect(policyEngineBindingFromConfig(publicConfig(false))).toBeUndefined();
  });

  it("refuses an endpoint without its pinned audience and grant issuer", () => {
    expect(() =>
      validateSharePublicConfig({
        ...rawConfig(true),
        policyEngineGrantIssuerDid: "not-a-did-key",
      }),
    ).toThrow(/policy engine binding is not enrolled/);
  });

  it("pins exactly the three origins the receiver may contact", () => {
    const config = publicConfig(true);
    const binding = policyEngineBindingFromConfig(config)!;
    expect(receiverOriginPolicy(config, binding).allowedOrigins).toEqual([
      CREDENTIALS_ORIGIN,
      NODE_ORIGIN,
      ENGINE_ORIGIN,
    ]);
  });
});

describe("share host policy engine proxy", () => {
  const bundle = validateTrustBundle({
    version: "tinycloud.share-email-trust-bundle/v1",
    shareOrigin: "https://share.tinycloud.xyz",
    returnOrigin: "https://share.tinycloud.xyz",
    registryOrigin: "https://registry.tinycloud.xyz",
    credentialsOrigin: CREDENTIALS_ORIGIN,
    emailOrigin: "https://email.tinycloud.xyz",
    policyEngineOrigin: ENGINE_ORIGIN,
    policyEngineAudience: "urn:tinycloud:policy-engine:prod",
    policyEngineGrantIssuerDid: GRANT_ISSUER_DID,
    nodeOrigin: NODE_ORIGIN,
    nodeAudience: "did:web:node.tinycloud.xyz",
    nodeInvitationKid: "did:web:node.tinycloud.xyz#invite-1",
    nodeInvitationPublicKey: Buffer.from(new Uint8Array(32).fill(1)).toString(
      "base64url",
    ),
    nodeKeyVersion: 1,
    nodeEnabled: true,
    issuerDid: "did:web:witness.credentials.org",
    issuerVct: "opencredentials.email/v1",
    issuerKid: "did:web:witness.credentials.org#key-1",
    issuerPublicKey: Buffer.from(new Uint8Array(32).fill(2)).toString(
      "base64url",
    ),
    issuerKeyVersion: 1,
    issuerEnabled: true,
  });

  it("routes only the two frozen v0 routes, and to the engine not the node", () => {
    for (const path of POLICY_ENGINE_ROUTES) {
      expect(upstreamForPath(bundle, path, {})).toEqual({
        service: "policy-engine",
        origin: ENGINE_ORIGIN,
      });
    }
    expect(upstreamForPath(bundle, "/policy/v0/policies/x/active-cutoff", {})).toBeUndefined();
  });

  it("keeps the generic node capability routes on the node", () => {
    for (const path of ["/delegate", "/invoke"]) {
      expect(upstreamForPath(bundle, path, {})).toEqual({
        service: "node",
        origin: NODE_ORIGIN,
      });
    }
  });
});

describe("accountless receiver read", () => {
  it("reads and decrypts without a single node share route", async () => {
    const config = publicConfig(true);
    const binding = policyEngineBindingFromConfig(config)!;
    const holder = createEphemeralHolderKey({ seed: new Uint8Array(32).fill(8) });
    const contentKey = new Uint8Array(32).fill(12);
    const body = "# shared with you\n";

    const nonce = new Uint8Array(12).fill(4);
    const aesKey = await crypto.subtle.importKey(
      "raw",
      contentKey,
      "AES-GCM",
      false,
      ["encrypt"],
    );
    const sealed = new Uint8Array(
      await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: nonce },
        aesKey,
        new TextEncoder().encode(body),
      ),
    );
    const ciphertext = Uint8Array.from([0x01, ...nonce, ...sealed]);

    const CAPABILITY_HASH = requestedCapabilitiesHashHex([
      {
        service: "tinycloud.kv",
        space: CAPABILITY_SPACE,
        path: RESOURCE_PATH,
        actions: ["tinycloud.kv/get"],
      },
    ]);
    const seconds = Math.floor(Date.now() / 1000);
    const header = { alg: "EdDSA", typ: "JWT", ucv: "0.10.0" };
    const payload = {
      iss: `${GRANT_ISSUER_DID}#${GRANT_ISSUER_DID.slice("did:key:".length)}`,
      aud: holder.did,
      att: {
        [`${CAPABILITY_SPACE}/kv/${RESOURCE_PATH}`]: {
          "tinycloud.kv/get": [{}],
        },
      },
      prf: ["bafyparent"],
      nbf: seconds,
      exp: seconds + 120,
      fct: [
        {
          "xyz.tinycloud.policy/delegationMode": "terminal",
          "xyz.tinycloud.policy/policyId": POLICY_ID,
          "xyz.tinycloud.policy/capabilityHashHex": CAPABILITY_HASH,
          "xyz.tinycloud.policy/revocationMode": "refresh_only",
          "xyz.tinycloud.policy/issuanceId": "iss_share_1",
        },
      ],
    };
    const signingInput = `${Buffer.from(JSON.stringify(header)).toString(
      "base64url",
    )}.${Buffer.from(JSON.stringify(payload)).toString("base64url")}`;
    const encoded = `${signingInput}.${Buffer.from(
      ed25519.sign(new TextEncoder().encode(signingInput), GRANT_ISSUER_SEED),
    ).toString("base64url")}`;
    const rfc = (value: number) =>
      new Date(value * 1000).toISOString().replace(".000Z", "Z");

    const trace: string[] = [];
    const transport = {
      async request(request: { method: string; url: string; body?: unknown }) {
        const url = new URL(request.url);
        trace.push(`${request.method} ${url.origin}${url.pathname}`);
        if (url.pathname === "/policy/v0/challenge") {
          return {
            status: 200,
            finalUrl: request.url,
            body: {
              challenge: {
                schema: "xyz.tinycloud.policy/challenge/v0",
                challengeId: "chal_share",
                policyId: POLICY_ID,
                audience: binding.audience,
                nonce: "q".repeat(43),
                challengeExpiresAt: new Date(Date.now() + 300_000).toISOString(),
                acceptedSuites: ["eddsa-ed25519-sha256-jcs-v1"],
              },
            },
          };
        }
        if (url.pathname === "/policy/v0/resolve") {
          return {
            status: 200,
            finalUrl: request.url,
            body: {
              delegation: {
                delegationId: deriveDelegationCid(encoded),
                issuanceId: "iss_share_1",
                issuerDid: GRANT_ISSUER_DID,
                holderDid: holder.did,
                policyId: POLICY_ID,
                capabilityHashHex: CAPABILITY_HASH,
                revocationMode: "refresh_only",
                issuedAt: rfc(seconds),
                expiresAt: rfc(seconds + 120),
                terminal: true,
                encoded,
              },
            },
          };
        }
        if (url.pathname === "/delegate") {
          return {
            status: 200,
            finalUrl: request.url,
            body: { activated: [NODE_SPACE_ID], skipped: [] },
          };
        }
        if (url.pathname === "/invoke") {
          return { status: 200, finalUrl: request.url, body: ciphertext };
        }
        throw new Error(`unexpected request ${request.url}`);
      },
    };

    const result = await readAccountlessShare({
      config,
      binding,
      policyId: POLICY_ID,
      capabilitySpace: CAPABILITY_SPACE,
      nodeSpaceId: NODE_SPACE_ID,
      resourcePath: RESOURCE_PATH,
      requirementId: "exact-email",
      credential: "eyJ.share.sd-jwt",
      contentKey,
      holder,
      invoke: () => ({ Authorization: "invocation" }),
      transport,
    });

    expect(new TextDecoder().decode(result.plaintext)).toBe(body);
    expect(trace).toEqual([
      `POST ${ENGINE_ORIGIN}/policy/v0/challenge`,
      `POST ${ENGINE_ORIGIN}/policy/v0/resolve`,
      `POST ${NODE_ORIGIN}/delegate`,
      `POST ${NODE_ORIGIN}/invoke`,
    ]);
    expect(trace.some((entry) => entry.includes("/share/"))).toBe(false);
  });
});
