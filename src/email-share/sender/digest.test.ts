import { describe, expect, it } from "vitest";

import { canonicalDigest } from "./digest.js";

describe("canonicalDigest", () => {
  it("matches the known base64url(sha256(UTF8(JCS(value)))) digest", async () => {
    // From test/vectors/email-claim-v1/positive.json scenario "kv":
    // preimages.authorizationRequest.digest, computed over the same body.
    const body = {
      shareCid: "bafkreiekhtgxpb5xhykd6pytalpkmg52trryror2gritt7r56jv2t75fl4",
      shareId: "share-kv-001",
      policyCid: "bafkreiaqkcd56bhbn3zwcx7r5xdkle2nukcrhkvwwrcg4qqehk6q5hlwi4",
      recipientEmail: "Alice+Notes@example.com",
      targetOrigin: "https://node.example",
      nodeAudience: "did:web:node.example",
      action: "tinycloud.kv/get",
      resource: "documents/plan.md",
      requestBodyDigest: "6VKCIl6k-KeSgqTFHaX3f_XUgqxxvat7swcsf2CVIQM",
    };
    await expect(canonicalDigest(body)).resolves.toBe(
      "3KkEHCL6_vOmIzNzaatIvP1v9qHeEgW2JKg2bT7371c",
    );
  });

  it("is order-independent (canonicalization sorts keys)", async () => {
    const a = await canonicalDigest({ a: 1, b: 2 });
    const b = await canonicalDigest({ b: 2, a: 1 });
    expect(a).toBe(b);
  });

  it("rejects non-canonicalizable values", async () => {
    await expect(canonicalDigest({ a: Number.POSITIVE_INFINITY })).rejects.toThrow();
  });
});
