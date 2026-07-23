import { describe, expect, it } from "vitest";

import { positiveUnsignedEnvelope, shippingVerifiedEnvelope, shippingVerifiedEnvelopeFrom } from "./envelope-fixture.test-support.js";
import { canonicalDigest } from "./digest.js";
import {
  authorizationAgreesWithPreparedInputs,
  prepareInvitationInputs,
  shareUrlAgreesWithPreparedInputs,
  type InviteAuthorization,
  type PreparedInvitationInputs,
} from "./invitation-input.js";

const SPACE = "did:pkh:eip155:1:0x1111111111111111111111111111111111111111";

async function prepared(kind: "kv" | "sql" = "kv") {
  return prepareInvitationInputs(await shippingVerifiedEnvelope(kind));
}

function validAuthorization(input: PreparedInvitationInputs): InviteAuthorization {
  return {
    type: "TinyCloudShareInviteAuthorization",
    version: 1,
    jti: "AQIDBAUGBwgJCgsMDQ4PEA",
    senderDid: input.senderDid,
    shareCid: input.authorizationRequest.shareCid,
    shareId: input.authorizationRequest.shareId,
    policyCid: input.policyCid,
    recipientEmail: input.policy.recipientEmail,
    targetOrigin: input.authorizationRequest.targetOrigin,
    nodeAudience: input.authorizationRequest.nodeAudience,
    returnOrigin: "https://share.tinycloud.xyz",
    documentName: input.documentName,
    senderTrust: "verified",
    contentSource: input.policy.contentSource,
    contentSourceDigest: input.policy.contentSourceDigest,
    shareExpiresAt: input.policy.expiresAt,
    issuedAt: "2026-07-16T12:00:00.000Z",
    expiresAt: "2026-07-16T12:05:00.000Z",
    reportAbuseToken: "4OHi4-Tl5ufo6err7O3u7w",
  };
}

describe("prepareInvitationInputs", () => {
  it("rebuilds the frozen policy and authorization request after factory verification", async () => {
    const input = await prepared();
    expect(input.policy).toEqual({
      type: "TinyCloudSharePolicy",
      version: 1,
      recipientEmail: "Alice+Notes@example.com",
      contentSource: {
        kind: "kv",
        space: SPACE,
        path: "documents/plan.md",
        action: "tinycloud.kv/get",
      },
      contentSourceDigest: "B-O75gHmIx2CyOm9cOdHJivP-kupRtNWcUPXuZbEnZ4",
      action: "tinycloud.kv/get",
      resource: "documents/plan.md",
      expiresAt: "2026-07-23T12:00:00.000Z",
      issuerDid: input.senderDid,
    });
    expect(input.policyCid).toBe("bafkreiaqkcd56bhbn3zwcx7r5xdkle2nukcrhkvwwrcg4qqehk6q5hlwi4");
    const { requestBodyDigest: _digest, ...unsignedRequest } = input.authorizationRequest;
    expect(input.authorizationRequest.requestBodyDigest).toBe(await canonicalDigest(unsignedRequest));
  });

  it("supports the frozen SQL source through the same factory and binding path", async () => {
    const input = await prepared("sql");
    expect(input.policy.contentSource.kind).toBe("sql");
    expect(input.policy.action).toBe("tinycloud.sql/read");
  });
});

describe("authorizationAgreesWithPreparedInputs", () => {
  it("accepts an authorization that agrees on every cross-checked field", async () => {
    const input = await prepared();
    expect(authorizationAgreesWithPreparedInputs(input, validAuthorization(input))).toBe(true);
  });

  const mismatches: Array<[string, (authorization: InviteAuthorization) => InviteAuthorization]> = [
    ["shareCid", (authorization) => ({ ...authorization, shareCid: "bafkreiekhtgxpb5xhykd6pytalpkmg52trryror2gritt7r56jv2t75fl5" })],
    ["policyCid", (authorization) => ({ ...authorization, policyCid: "bafkreiaqkcd56bhbn3zwcx7r5xdkle2nukcrhkvwwrcg4qqehk6q5hlwi5" })],
    ["recipientEmail", (authorization) => ({ ...authorization, recipientEmail: "eve@example.com" })],
    ["targetOrigin", (authorization) => ({ ...authorization, targetOrigin: "https://attacker.example" })],
    ["nodeAudience", (authorization) => ({ ...authorization, nodeAudience: "did:web:attacker.example" })],
    ["documentName", (authorization) => ({ ...authorization, documentName: "Other name.md" })],
  ];

  it.each(mismatches)("rejects an authorization with a wrong %s", async (_field, mutate) => {
    const input = await prepared();
    const authorization = mutate(validAuthorization(input));
    expect(authorizationAgreesWithPreparedInputs(input, authorization)).toBe(false);
  });
});

describe("documentName UTF-8 boundary", () => {
  it("accepts exactly 200 UTF-8 bytes through factory and policy binding", async () => {
    const unsigned = positiveUnsignedEnvelope("kv");
    const documentName = `${"a".repeat(198)}é`;
    expect(new TextEncoder().encode(documentName).length).toBe(200);
    const custom = { ...unsigned, display: { ...unsigned.display, filename: documentName } };
    await expect(prepareInvitationInputs(await shippingVerifiedEnvelopeFrom(custom))).resolves.toMatchObject({
      documentName,
    });
  });

  it("rejects 201 UTF-8 bytes specifically at the name boundary", async () => {
    const unsigned = positiveUnsignedEnvelope("kv");
    const documentName = `${"a".repeat(199)}é`;
    expect(new TextEncoder().encode(documentName).length).toBe(201);
    const custom = { ...unsigned, display: { ...unsigned.display, filename: documentName } };
    await expect(prepareInvitationInputs(await shippingVerifiedEnvelopeFrom(custom))).rejects.toThrow(
      /document name exceeds 200 UTF-8 bytes/,
    );
  });
});

describe("shareUrlAgreesWithPreparedInputs", () => {
  it("accepts only the canonical share origin and prepared CID", async () => {
    const input = await prepared();
    const valid = `https://share.tinycloud.xyz/s/${input.authorizationRequest.shareCid}#k=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8`;
    expect(shareUrlAgreesWithPreparedInputs(input, valid)).toBe(true);
    expect(shareUrlAgreesWithPreparedInputs(input, valid.replace("https://share.tinycloud.xyz", "https://share.tinycloud.xyz:443"))).toBe(false);
    expect(shareUrlAgreesWithPreparedInputs(input, valid.replace("/s/", "/s/./"))).toBe(false);
    expect(shareUrlAgreesWithPreparedInputs(input, valid.replace("#k=", "?x=1#k="))).toBe(false);
  });
});
