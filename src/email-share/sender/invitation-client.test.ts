import { describe, expect, it } from "vitest";

import { SenderHttpError, SenderInvalidResponseError, SenderNetworkError } from "./errors.js";
import { requestInvitation } from "./invitation-client.js";
import type { CreateInvitationRequestBody } from "./invitation-client.js";

const REQUEST_BODY: CreateInvitationRequestBody = {
  authorization: {
    type: "TinyCloudShareInviteAuthorization",
    version: 1,
    jti: "AQIDBAUGBwgJCgsMDQ4PEA",
    senderDid: "did:key:z6MktwtqAzuD5F77tAMBMwNs1KybZeff61EehV9xB1ZpXQG7",
    shareCid: "bafkreiekhtgxpb5xhykd6pytalpkmg52trryror2gritt7r56jv2t75fl4",
    shareId: "share-kv-001",
    policyCid: "bafkreiaqkcd56bhbn3zwcx7r5xdkle2nukcrhkvwwrcg4qqehk6q5hlwi4",
    recipientEmail: "Alice+Notes@example.com",
    targetOrigin: "https://node.example",
    nodeAudience: "did:web:node.example",
    returnOrigin: "https://share.tinycloud.xyz",
    documentName: "Project plan.md",
    senderTrust: "verified",
    contentSource: {
      kind: "kv",
      space: "did:pkh:eip155:1:0x1111111111111111111111111111111111111111",
      path: "documents/plan.md",
      action: "tinycloud.kv/get",
    },
    contentSourceDigest: "B-O75gHmIx2CyOm9cOdHJivP-kupRtNWcUPXuZbEnZ4",
    shareExpiresAt: "2026-07-23T12:00:00.000Z",
    issuedAt: "2026-07-16T12:00:00.000Z",
    expiresAt: "2026-07-16T12:05:00.000Z",
    reportAbuseToken: "4OHi4-Tl5ufo6err7O3u7w",
  },
  proof: {
    alg: "EdDSA",
    kid: "did:web:node.example#invitation-key-1",
    signature: "jL6f77-Kddr2DlUWrSMtnQ8DHnKiR4NkvWmVS-6zvLMpKmsz7qllGICQ_DZiJmJEwCEShijWhOramvMA9ix9Bw",
  },
  shareUrl:
    "https://share.tinycloud.xyz/s/bafkreiekhtgxpb5xhykd6pytalpkmg52trryror2gritt7r56jv2t75fl4#k=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
};

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

describe("requestInvitation", () => {
  it("returns the fixed success shape", async () => {
    const fetchFn = (async () =>
      jsonResponse(200, { status: "accepted", retryAfterSeconds: 20 })) as typeof fetch;

    const result = await requestInvitation(
      "https://node.example/invite/create",
      REQUEST_BODY,
      { fetchFn },
    );

    expect(result).toEqual({ status: "accepted", retryAfterSeconds: 20 });
  });

  it("throws SenderNetworkError when the network fails", async () => {
    const fetchFn = (async () => {
      throw new TypeError("network down");
    }) as typeof fetch;

    await expect(
      requestInvitation("https://node.example/invite/create", REQUEST_BODY, { fetchFn }),
    ).rejects.toBeInstanceOf(SenderNetworkError);
  });

  it("throws SenderHttpError on a non-2xx status", async () => {
    const fetchFn = (async () => jsonResponse(429, {})) as typeof fetch;

    await expect(
      requestInvitation("https://node.example/invite/create", REQUEST_BODY, { fetchFn }),
    ).rejects.toBeInstanceOf(SenderHttpError);
  });

  it("throws SenderInvalidResponseError on a body that is not JSON", async () => {
    const fetchFn = (async () =>
      new Response("not json", { status: 200, headers: { "content-type": "text/plain" } })) as typeof fetch;

    await expect(
      requestInvitation("https://node.example/invite/create", REQUEST_BODY, { fetchFn }),
    ).rejects.toBeInstanceOf(SenderInvalidResponseError);
  });

  it("throws SenderInvalidResponseError on a wrong retryAfterSeconds", async () => {
    const fetchFn = (async () =>
      jsonResponse(200, { status: "accepted", retryAfterSeconds: 5 })) as typeof fetch;

    await expect(
      requestInvitation("https://node.example/invite/create", REQUEST_BODY, { fetchFn }),
    ).rejects.toBeInstanceOf(SenderInvalidResponseError);
  });

  it("throws SenderInvalidResponseError on an unexpected status value", async () => {
    const fetchFn = (async () =>
      jsonResponse(200, { status: "pending", retryAfterSeconds: 20 })) as typeof fetch;

    await expect(
      requestInvitation("https://node.example/invite/create", REQUEST_BODY, { fetchFn }),
    ).rejects.toBeInstanceOf(SenderInvalidResponseError);
  });
});
