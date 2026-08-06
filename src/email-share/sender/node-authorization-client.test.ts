import { describe, expect, it } from "vitest";

import { SenderHttpError, SenderInvalidResponseError, SenderNetworkError } from "./errors.js";
import { requestNodeAuthorization } from "./node-authorization-client.js";

const REQUEST_BODY = {
  shareCid: "bafkreiekhtgxpb5xhykd6pytalpkmg52trryror2gritt7r56jv2t75fl4",
  shareId: "share-kv-001",
  policyCid: "bafkreiaqkcd56bhbn3zwcx7r5xdkle2nukcrhkvwwrcg4qqehk6q5hlwi4",
  recipientEmail: "Alice+Notes@example.com",
  targetOrigin: "https://node.example",
  nodeAudience: "did:web:node.example",
  action: "tinycloud.kv/get" as const,
  resource: "documents/plan.md",
  requestBodyDigest: "6VKCIl6k-KeSgqTFHaX3f_XUgqxxvat7swcsf2CVIQM",
};

const AUTHORIZATION = {
  type: "TinyCloudShareInviteAuthorization" as const,
  version: 1 as const,
  jti: "AQIDBAUGBwgJCgsMDQ4PEA",
  senderDid: "did:key:z6MktwtqAzuD5F77tAMBMwNs1KybZeff61EehV9xB1ZpXQG7",
  shareCid: REQUEST_BODY.shareCid,
  shareId: REQUEST_BODY.shareId,
  policyCid: REQUEST_BODY.policyCid,
  recipientEmail: REQUEST_BODY.recipientEmail,
  targetOrigin: REQUEST_BODY.targetOrigin,
  nodeAudience: REQUEST_BODY.nodeAudience,
  returnOrigin: "https://share.tinycloud.xyz" as const,
  documentName: "Project plan.md",
  senderTrust: "verified" as const,
  contentSource: {
    kind: "kv" as const,
    space: "did:pkh:eip155:1:0x1111111111111111111111111111111111111111",
    path: "documents/plan.md",
    action: "tinycloud.kv/get" as const,
  },
  contentSourceDigest: "B-O75gHmIx2CyOm9cOdHJivP-kupRtNWcUPXuZbEnZ4",
  shareExpiresAt: "2026-07-23T12:00:00.000Z",
  issuedAt: "2026-07-16T12:00:00.000Z",
  expiresAt: "2026-07-16T12:05:00.000Z",
  reportAbuseToken: "4OHi4-Tl5ufo6err7O3u7w",
};

const PROOF = {
  alg: "EdDSA" as const,
  kid: "did:web:node.example#invitation-key-1",
  signature: "jL6f77-Kddr2DlUWrSMtnQ8DHnKiR4NkvWmVS-6zvLMpKmsz7qllGICQ_DZiJmJEwCEShijWhOramvMA9ix9Bw",
};

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

describe("requestNodeAuthorization", () => {
  it("returns the parsed authorization + proof on a strict-shape success", async () => {
    const fetchFn = (async () =>
      jsonResponse(200, { authorization: AUTHORIZATION, proof: PROOF })) as typeof fetch;

    const result = await requestNodeAuthorization(
      "https://node.example/invite/authorization",
      REQUEST_BODY,
      { fetchFn },
    );

    expect(result).toEqual({ authorization: AUTHORIZATION, proof: PROOF });
  });

  it("throws SenderNetworkError when the network fails", async () => {
    const fetchFn = (async () => {
      throw new TypeError("network down");
    }) as typeof fetch;

    await expect(
      requestNodeAuthorization("https://node.example/invite/authorization", REQUEST_BODY, {
        fetchFn,
      }),
    ).rejects.toBeInstanceOf(SenderNetworkError);
  });

  it("throws SenderHttpError on a non-2xx status", async () => {
    const fetchFn = (async () => jsonResponse(503, {})) as typeof fetch;

    await expect(
      requestNodeAuthorization("https://node.example/invite/authorization", REQUEST_BODY, {
        fetchFn,
      }),
    ).rejects.toBeInstanceOf(SenderHttpError);
  });

  it("throws SenderInvalidResponseError on a body that is not JSON", async () => {
    const fetchFn = (async () =>
      new Response("not json", { status: 200, headers: { "content-type": "text/plain" } })) as typeof fetch;

    await expect(
      requestNodeAuthorization("https://node.example/invite/authorization", REQUEST_BODY, {
        fetchFn,
      }),
    ).rejects.toBeInstanceOf(SenderInvalidResponseError);
  });

  it("throws SenderInvalidResponseError when a required authorization field is missing", async () => {
    const { documentName: _documentName, ...withoutDocumentName } = AUTHORIZATION;
    const fetchFn = (async () =>
      jsonResponse(200, { authorization: withoutDocumentName, proof: PROOF })) as typeof fetch;

    await expect(
      requestNodeAuthorization("https://node.example/invite/authorization", REQUEST_BODY, {
        fetchFn,
      }),
    ).rejects.toBeInstanceOf(SenderInvalidResponseError);
  });

  it("throws SenderInvalidResponseError when proof is malformed", async () => {
    const fetchFn = (async () =>
      jsonResponse(200, { authorization: AUTHORIZATION, proof: { alg: "EdDSA" } })) as typeof fetch;

    await expect(
      requestNodeAuthorization("https://node.example/invite/authorization", REQUEST_BODY, {
        fetchFn,
      }),
    ).rejects.toBeInstanceOf(SenderInvalidResponseError);
  });

  it("throws SenderInvalidResponseError when an unknown top-level field is present", async () => {
    const fetchFn = (async () =>
      jsonResponse(200, { authorization: AUTHORIZATION, proof: PROOF, extra: true })) as typeof fetch;

    await expect(
      requestNodeAuthorization("https://node.example/invite/authorization", REQUEST_BODY, {
        fetchFn,
      }),
    ).rejects.toBeInstanceOf(SenderInvalidResponseError);
  });

  it.each([
    ["jti", "not-base64url-jti"],
    ["senderDid", "not-a-did"],
    ["shareCid", "not-a-cid"],
    ["shareId", ""],
    ["policyCid", "not-a-cid"],
    ["recipientEmail", "not an email"],
    ["targetOrigin", "http://node.example"],
    ["nodeAudience", "not-a-did"],
    ["contentSourceDigest", "not-a-digest"],
    ["shareExpiresAt", "2026-07-23"],
    ["issuedAt", "2026-07-16T12:00:00Z"],
    ["expiresAt", "not-a-timestamp"],
    ["reportAbuseToken", "not-base64url"],
  ])(
    "throws SenderInvalidResponseError when authorization.%s is malformed",
    async (field, badValue) => {
      const fetchFn = (async () =>
        jsonResponse(200, {
          authorization: { ...AUTHORIZATION, [field]: badValue },
          proof: PROOF,
        })) as typeof fetch;

      await expect(
        requestNodeAuthorization("https://node.example/invite/authorization", REQUEST_BODY, {
          fetchFn,
        }),
      ).rejects.toBeInstanceOf(SenderInvalidResponseError);
    },
  );

  it("throws SenderInvalidResponseError when documentName exceeds 200 UTF-8 bytes", async () => {
    const fetchFn = (async () =>
      jsonResponse(200, {
        authorization: { ...AUTHORIZATION, documentName: "x".repeat(201) },
        proof: PROOF,
      })) as typeof fetch;

    await expect(
      requestNodeAuthorization("https://node.example/invite/authorization", REQUEST_BODY, {
        fetchFn,
      }),
    ).rejects.toBeInstanceOf(SenderInvalidResponseError);
  });

  it("throws SenderInvalidResponseError when documentName contains a control character", async () => {
    const fetchFn = (async () =>
      jsonResponse(200, {
        authorization: { ...AUTHORIZATION, documentName: "plan\nname.md" },
        proof: PROOF,
      })) as typeof fetch;

    await expect(
      requestNodeAuthorization("https://node.example/invite/authorization", REQUEST_BODY, {
        fetchFn,
      }),
    ).rejects.toBeInstanceOf(SenderInvalidResponseError);
  });

  it("throws SenderInvalidResponseError when proof.kid is malformed", async () => {
    const fetchFn = (async () =>
      jsonResponse(200, {
        authorization: AUTHORIZATION,
        proof: { ...PROOF, kid: "not-a-kid" },
      })) as typeof fetch;

    await expect(
      requestNodeAuthorization("https://node.example/invite/authorization", REQUEST_BODY, {
        fetchFn,
      }),
    ).rejects.toBeInstanceOf(SenderInvalidResponseError);
  });

  it("throws SenderInvalidResponseError when proof.signature is malformed", async () => {
    const fetchFn = (async () =>
      jsonResponse(200, {
        authorization: AUTHORIZATION,
        proof: { ...PROOF, signature: "not-base64url-of-64-bytes" },
      })) as typeof fetch;

    await expect(
      requestNodeAuthorization("https://node.example/invite/authorization", REQUEST_BODY, {
        fetchFn,
      }),
    ).rejects.toBeInstanceOf(SenderInvalidResponseError);
  });
});
