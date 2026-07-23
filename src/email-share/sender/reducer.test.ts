import { describe, expect, it } from "vitest";

import { shippingVerifiedEnvelope } from "./envelope-fixture.test-support.js";
import { prepareInvitationInputs, type InviteAuthorization } from "./invitation-input.js";
import { INVITATION_REQUESTED_TEXT, sendEmailInvitation } from "./reducer.js";

const SPACE = "did:pkh:eip155:1:0x1111111111111111111111111111111111111111";
const ISSUER_DID = "did:key:z6MktwtqAzuD5F77tAMBMwNs1KybZeff61EehV9xB1ZpXQG7";
const SHARE_CID = "bafkreiekhtgxpb5xhykd6pytalpkmg52trryror2gritt7r56jv2t75fl4";
const NODE_DID = "did:web:node.example";
const ORIGIN = "https://node.example";
let SHARE_URL = "";
// From test/vectors/email-claim-v1/positive.json scenario "kv" (manifest-pinned).
const POLICY_CID = "bafkreiaqkcd56bhbn3zwcx7r5xdkle2nukcrhkvwwrcg4qqehk6q5hlwi4";
const POLICY_BYTES =
  "eyJhY3Rpb24iOiJ0aW55Y2xvdWQua3YvZ2V0IiwiY29udGVudFNvdXJjZSI6eyJhY3Rpb24iOiJ0aW55Y2xvdWQua3YvZ2V0Iiwia2luZCI6Imt2IiwicGF0aCI6ImRvY3VtZW50cy9wbGFuLm1kIiwic3BhY2UiOiJkaWQ6cGtoOmVpcDE1NToxOjB4MTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMSJ9LCJjb250ZW50U291cmNlRGlnZXN0IjoiQi1PNzVnSG1JeDJDeU9tOWNPZEhKaXZQLWt1cFJ0TldjVVBYdVpiRW5aNCIsImV4cGlyZXNBdCI6IjIwMjYtMDctMjNUMTI6MDA6MDAuMDAwWiIsImlzc3VlckRpZCI6ImRpZDprZXk6ejZNa3R3dHFBenVENUY3N3RBTUJNd05zMUt5YlplZmY2MUVlaFY5eEIxWnBYUUc3IiwicmVjaXBpZW50RW1haWwiOiJBbGljZStOb3Rlc0BleGFtcGxlLmNvbSIsInJlc291cmNlIjoiZG9jdW1lbnRzL3BsYW4ubWQiLCJ0eXBlIjoiVGlueUNsb3VkU2hhcmVQb2xpY3kiLCJ2ZXJzaW9uIjoxfQ";

async function prepared() {
  const input = await prepareInvitationInputs(await shippingVerifiedEnvelope("kv"));
  SHARE_URL = `https://share.tinycloud.xyz/s/${input.authorizationRequest.shareCid}#k=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8`;
  return input;
}

function authorizationFor(
  input: Awaited<ReturnType<typeof prepared>>,
): InviteAuthorization {
  return {
    type: "TinyCloudShareInviteAuthorization",
    version: 1,
    jti: "AQIDBAUGBwgJCgsMDQ4PEA",
    senderDid: ISSUER_DID,
    shareCid: input.authorizationRequest.shareCid,
    shareId: input.authorizationRequest.shareId,
    policyCid: input.policyCid,
    recipientEmail: input.policy.recipientEmail,
    targetOrigin: input.authorizationRequest.targetOrigin,
    nodeAudience: input.authorizationRequest.nodeAudience,
    returnOrigin: "https://share.tinycloud.xyz",
    documentName: "Project plan.md",
    senderTrust: "verified",
    contentSource: input.policy.contentSource,
    contentSourceDigest: input.policy.contentSourceDigest,
    shareExpiresAt: input.policy.expiresAt,
    issuedAt: "2026-07-16T12:00:00.000Z",
    expiresAt: "2026-07-16T12:05:00.000Z",
    reportAbuseToken: "4OHi4-Tl5ufo6err7O3u7w",
  };
}

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

describe("sendEmailInvitation", () => {
  it("rejects a forged prepared object before the first fetch", async () => {
    const input = await prepared();
    const forged = {
      policy: input.policy,
      policyBytes: input.policyBytes,
      policyCid: input.policyCid,
      authorizationRequest: input.authorizationRequest,
      senderDid: input.senderDid,
      documentName: input.documentName,
    } as Parameters<typeof sendEmailInvitation>[0];
    let called = false;
    const fetchFn = (async () => {
      called = true;
      return jsonResponse(200, {});
    }) as typeof fetch;

    const result = await sendEmailInvitation(forged, SHARE_URL, {
      nodeAuthorizationUrl: "https://node.example/share/v1/invitations/authorize",
      invitationUrl: "https://witness.credentials.org/v1/share-email/invitations",
      fetchFn,
    });

    expect(result).toEqual({
      status: "failed",
      statusText: "We couldn't request this invitation. Please try again.",
    });
    expect(called).toBe(false);
  });

  it("returns the exact success text on a clean round trip", async () => {
    const input = await prepared();
    const authorization = authorizationFor(input);
    const fetchFn = (async (url: string | URL | Request) => {
      if (String(url).includes("invitations/authorize")) {
        return jsonResponse(200, { authorization, proof: PROOF });
      }
      return jsonResponse(200, { status: "accepted", retryAfterSeconds: 20 });
    }) as typeof fetch;

    const result = await sendEmailInvitation(input, SHARE_URL, {
      nodeAuthorizationUrl: "https://node.example/share/v1/invitations/authorize",
      invitationUrl: "https://witness.credentials.org/v1/share-email/invitations",
      fetchFn,
    });

    expect(result).toEqual({ status: "requested", statusText: "Invitation requested" });
    expect(result.status === "requested" && result.statusText).toBe(INVITATION_REQUESTED_TEXT);
  });

  it("never reports delivery — success text is exactly 'Invitation requested'", async () => {
    const input = await prepared();
    const authorization = authorizationFor(input);
    const fetchFn = (async (url: string | URL | Request) =>
      String(url).includes("invitations/authorize")
        ? jsonResponse(200, { authorization, proof: PROOF })
        : jsonResponse(200, { status: "accepted", retryAfterSeconds: 20 })) as typeof fetch;

    const result = await sendEmailInvitation(input, SHARE_URL, {
      nodeAuthorizationUrl: "https://node.example/share/v1/invitations/authorize",
      invitationUrl: "https://witness.credentials.org/v1/share-email/invitations",
      fetchFn,
    });

    const text = result.status === "requested" ? result.statusText : "";
    expect(text).not.toMatch(/deliver/i);
    expect(text).toBe("Invitation requested");
  });

  it("fails closed when the node authorization disagrees on recipientEmail", async () => {
    const input = await prepared();
    const authorization = { ...authorizationFor(input), recipientEmail: "eve@example.com" };
    const fetchFn = (async (url: string | URL | Request) =>
      String(url).includes("invitations/authorize")
        ? jsonResponse(200, { authorization, proof: PROOF })
        : jsonResponse(200, { status: "accepted", retryAfterSeconds: 20 })) as typeof fetch;

    const result = await sendEmailInvitation(input, SHARE_URL, {
      nodeAuthorizationUrl: "https://node.example/share/v1/invitations/authorize",
      invitationUrl: "https://witness.credentials.org/v1/share-email/invitations",
      fetchFn,
    });

    expect(result.status).toBe("failed");
    expect(result.status === "failed" && result.statusText).not.toMatch(/eve@example\.com/);
  });

  it("fails closed when the node authorization disagrees on shareCid", async () => {
    const input = await prepared();
    const authorization = {
      ...authorizationFor(input),
      shareCid: "bafkreiekhtgxpb5xhykd6pytalpkmg52trryror2gritt7r56jv2t75fl5",
    };
    const fetchFn = (async () => jsonResponse(200, { authorization, proof: PROOF })) as typeof fetch;

    const result = await sendEmailInvitation(input, SHARE_URL, {
      nodeAuthorizationUrl: "https://node.example/share/v1/invitations/authorize",
      invitationUrl: "https://witness.credentials.org/v1/share-email/invitations",
      fetchFn,
    });

    expect(result.status).toBe("failed");
  });

  it("fails closed when the node authorization disagrees on targetOrigin/nodeAudience", async () => {
    const input = await prepared();
    const authorization = {
      ...authorizationFor(input),
      targetOrigin: "https://attacker.example",
      nodeAudience: "did:web:attacker.example",
    };
    const fetchFn = (async () => jsonResponse(200, { authorization, proof: PROOF })) as typeof fetch;

    const result = await sendEmailInvitation(input, SHARE_URL, {
      nodeAuthorizationUrl: "https://node.example/share/v1/invitations/authorize",
      invitationUrl: "https://witness.credentials.org/v1/share-email/invitations",
      fetchFn,
    });

    expect(result.status).toBe("failed");
  });

  it("reports a generic failure on a malformed authorization response", async () => {
    const input = await prepared();
    const fetchFn = (async () => jsonResponse(200, { nonsense: true })) as typeof fetch;

    const result = await sendEmailInvitation(input, SHARE_URL, {
      nodeAuthorizationUrl: "https://node.example/share/v1/invitations/authorize",
      invitationUrl: "https://witness.credentials.org/v1/share-email/invitations",
      fetchFn,
    });

    expect(result.status).toBe("failed");
  });

  it("reports a generic unavailable state when the network fails", async () => {
    const input = await prepared();
    const fetchFn = (async () => {
      throw new TypeError("network down");
    }) as typeof fetch;

    const result = await sendEmailInvitation(input, SHARE_URL, {
      nodeAuthorizationUrl: "https://node.example/share/v1/invitations/authorize",
      invitationUrl: "https://witness.credentials.org/v1/share-email/invitations",
      fetchFn,
    });

    expect(result.status).toBe("unavailable");
    expect(result.status === "unavailable" && result.statusText).not.toMatch(/network down/);
  });

  it("reports a generic unavailable state on a non-2xx node status", async () => {
    const input = await prepared();
    const fetchFn = (async () => jsonResponse(503, {})) as typeof fetch;

    const result = await sendEmailInvitation(input, SHARE_URL, {
      nodeAuthorizationUrl: "https://node.example/share/v1/invitations/authorize",
      invitationUrl: "https://witness.credentials.org/v1/share-email/invitations",
      fetchFn,
    });

    expect(result.status).toBe("unavailable");
  });

  it("fails closed on a share URL with the wrong origin, before any request is made", async () => {
    const input = await prepared();
    const shareUrl = SHARE_URL.replace("https://share.tinycloud.xyz", "https://attacker.example");
    let called = false;
    const fetchFn = (async () => {
      called = true;
      return jsonResponse(200, {});
    }) as typeof fetch;

    const result = await sendEmailInvitation(input, shareUrl, {
      nodeAuthorizationUrl: "https://node.example/share/v1/invitations/authorize",
      invitationUrl: "https://witness.credentials.org/v1/share-email/invitations",
      fetchFn,
    });

    expect(result.status).toBe("failed");
    expect(called).toBe(false);
  });

  it("fails closed on a share URL whose CID does not match the prepared shareCid", async () => {
    const input = await prepared();
    const shareUrl = SHARE_URL.replace(
      input.authorizationRequest.shareCid,
      "bafkreiekhtgxpb5xhykd6pytalpkmg52trryror2gritt7r56jv2t75fl5",
    );
    let called = false;
    const fetchFn = (async () => {
      called = true;
      return jsonResponse(200, {});
    }) as typeof fetch;

    const result = await sendEmailInvitation(input, shareUrl, {
      nodeAuthorizationUrl: "https://node.example/share/v1/invitations/authorize",
      invitationUrl: "https://witness.credentials.org/v1/share-email/invitations",
      fetchFn,
    });

    expect(result.status).toBe("failed");
    expect(called).toBe(false);
  });

  it("fails closed on a share URL with a query string", async () => {
    const input = await prepared();
    const shareUrl = SHARE_URL.replace("#k=", "?x=1#k=");
    let called = false;
    const fetchFn = (async () => {
      called = true;
      return jsonResponse(200, {});
    }) as typeof fetch;

    const result = await sendEmailInvitation(input, shareUrl, {
      nodeAuthorizationUrl: "https://node.example/share/v1/invitations/authorize",
      invitationUrl: "https://witness.credentials.org/v1/share-email/invitations",
      fetchFn,
    });

    expect(result.status).toBe("failed");
    expect(called).toBe(false);
  });

  it("fails closed on a share URL with a malformed fragment", async () => {
    const input = await prepared();
    const shareUrl = SHARE_URL.slice(0, -1);
    let called = false;
    const fetchFn = (async () => {
      called = true;
      return jsonResponse(200, {});
    }) as typeof fetch;

    const result = await sendEmailInvitation(input, shareUrl, {
      nodeAuthorizationUrl: "https://node.example/share/v1/invitations/authorize",
      invitationUrl: "https://witness.credentials.org/v1/share-email/invitations",
      fetchFn,
    });

    expect(result.status).toBe("failed");
    expect(called).toBe(false);
  });

  it("fails closed when the node authorization disagrees on shareId", async () => {
    const input = await prepared();
    const authorization = { ...authorizationFor(input), shareId: "share-kv-002" };
    const fetchFn = (async () => jsonResponse(200, { authorization, proof: PROOF })) as typeof fetch;

    const result = await sendEmailInvitation(input, SHARE_URL, {
      nodeAuthorizationUrl: "https://node.example/share/v1/invitations/authorize",
      invitationUrl: "https://witness.credentials.org/v1/share-email/invitations",
      fetchFn,
    });

    expect(result.status).toBe("failed");
  });

  it("fails closed when the node authorization disagrees on senderDid", async () => {
    const input = await prepared();
    const authorization = {
      ...authorizationFor(input),
      senderDid: "did:key:z6MktwtqAzuD5F77tAMBMwNs1KybZeff61EehV9xB1ZpXQG8",
    };
    const fetchFn = (async () => jsonResponse(200, { authorization, proof: PROOF })) as typeof fetch;

    const result = await sendEmailInvitation(input, SHARE_URL, {
      nodeAuthorizationUrl: "https://node.example/share/v1/invitations/authorize",
      invitationUrl: "https://witness.credentials.org/v1/share-email/invitations",
      fetchFn,
    });

    expect(result.status).toBe("failed");
  });

  it("fails closed when the node authorization disagrees on shareExpiresAt", async () => {
    const input = await prepared();
    const authorization = {
      ...authorizationFor(input),
      shareExpiresAt: "2099-01-01T00:00:00.000Z",
    };
    const fetchFn = (async () => jsonResponse(200, { authorization, proof: PROOF })) as typeof fetch;

    const result = await sendEmailInvitation(input, SHARE_URL, {
      nodeAuthorizationUrl: "https://node.example/share/v1/invitations/authorize",
      invitationUrl: "https://witness.credentials.org/v1/share-email/invitations",
      fetchFn,
    });

    expect(result.status).toBe("failed");
  });

  it("fails closed when the node authorization disagrees on documentName", async () => {
    const input = await prepared();
    const authorization = { ...authorizationFor(input), documentName: "Other name.md" };
    const fetchFn = (async () => jsonResponse(200, { authorization, proof: PROOF })) as typeof fetch;

    const result = await sendEmailInvitation(input, SHARE_URL, {
      nodeAuthorizationUrl: "https://node.example/share/v1/invitations/authorize",
      invitationUrl: "https://witness.credentials.org/v1/share-email/invitations",
      fetchFn,
    });

    expect(result.status).toBe("failed");
  });

  it("reports a generic unavailable state when the invitation endpoint is unreachable", async () => {
    const input = await prepared();
    const authorization = authorizationFor(input);
    const fetchFn = (async (url: string | URL | Request) => {
      if (String(url).includes("invitations/authorize")) {
        return jsonResponse(200, { authorization, proof: PROOF });
      }
      throw new TypeError("network down");
    }) as typeof fetch;

    const result = await sendEmailInvitation(input, SHARE_URL, {
      nodeAuthorizationUrl: "https://node.example/share/v1/invitations/authorize",
      invitationUrl: "https://witness.credentials.org/v1/share-email/invitations",
      fetchFn,
    });

    expect(result.status).toBe("unavailable");
  });

  describe("nodeAuthorizationUrl / invitationUrl binding", () => {
    async function expectNoFetchFailure(overrides: {
      nodeAuthorizationUrl?: string;
      invitationUrl?: string;
    }) {
      const input = await prepared();
      let called = false;
      const fetchFn = (async () => {
        called = true;
        return jsonResponse(200, {});
      }) as typeof fetch;

      const result = await sendEmailInvitation(input, SHARE_URL, {
        nodeAuthorizationUrl: "https://node.example/share/v1/invitations/authorize",
        invitationUrl: "https://witness.credentials.org/v1/share-email/invitations",
        ...overrides,
        fetchFn,
      });

      expect(result.status).toBe("failed");
      expect(called).toBe(false);
    }

    it("rejects a nodeAuthorizationUrl on the wrong origin", async () => {
      await expectNoFetchFailure({
        nodeAuthorizationUrl: "https://attacker.example/share/v1/invitations/authorize",
      });
    });

    it("rejects a nodeAuthorizationUrl with a different path", async () => {
      await expectNoFetchFailure({
        nodeAuthorizationUrl: "https://node.example/share/v1/invitations/authorize/extra",
      });
    });

    it("rejects a nodeAuthorizationUrl with userinfo", async () => {
      await expectNoFetchFailure({
        nodeAuthorizationUrl: "https://user:pass@node.example/share/v1/invitations/authorize",
      });
    });

    it("rejects a nodeAuthorizationUrl with a non-default port", async () => {
      await expectNoFetchFailure({
        nodeAuthorizationUrl: "https://node.example:8443/share/v1/invitations/authorize",
      });
    });

    it("rejects a nodeAuthorizationUrl with a query string", async () => {
      await expectNoFetchFailure({
        nodeAuthorizationUrl: "https://node.example/share/v1/invitations/authorize?x=1",
      });
    });

    it("rejects a nodeAuthorizationUrl with a fragment", async () => {
      await expectNoFetchFailure({
        nodeAuthorizationUrl: "https://node.example/share/v1/invitations/authorize#x",
      });
    });

    it("rejects an invitationUrl on the wrong (non-witness) origin", async () => {
      await expectNoFetchFailure({
        invitationUrl: "https://node.example/v1/share-email/invitations",
      });
    });

    it("rejects an invitationUrl with a different path", async () => {
      await expectNoFetchFailure({
        invitationUrl: "https://witness.credentials.org/v1/share-email/invitations/resend",
      });
    });

    it("rejects an invitationUrl with userinfo", async () => {
      await expectNoFetchFailure({
        invitationUrl: "https://user:pass@witness.credentials.org/v1/share-email/invitations",
      });
    });

    it("rejects an invitationUrl with a non-default port", async () => {
      await expectNoFetchFailure({
        invitationUrl: "https://witness.credentials.org:8443/v1/share-email/invitations",
      });
    });

    it("rejects an invitationUrl with a query string", async () => {
      await expectNoFetchFailure({
        invitationUrl: "https://witness.credentials.org/v1/share-email/invitations?x=1",
      });
    });

    it("rejects an invitationUrl with a fragment", async () => {
      await expectNoFetchFailure({
        invitationUrl: "https://witness.credentials.org/v1/share-email/invitations#x",
      });
    });
  });
});
