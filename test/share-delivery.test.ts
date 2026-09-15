import { describe, expect, it, vi } from "vitest";
import { requestAddressedDelivery } from "../src/share/delivery.js";

describe("addressed delivery boundary", () => {
  it("posts the unchanged node-authorized invitation only to OpenCredentials delivery", async () => {
    const credentialsOrigin = "https://credentials.example";
    const request = Object.freeze({ returnLink: "https://share.example/s/inline#v=2&p=sealed-policy" });
    const admission = Object.freeze({ schema: "xyz.tinycloud.policy/delivery-admission/v0" });
    const proof = Object.freeze({ alg: "EdDSA", kid: "did:web:node.example#key", signature: "test-signature" });
    const shareUrl = "https://share.example/s/inline#v=2&p=sealed-policy";
    const fetchFn = vi.fn<typeof fetch>(async () => new Response(null, { status: 202 }));

    await requestAddressedDelivery({
      credentialsOrigin,
      shareUrl,
      deliveryAuthorization: { request, admission, proof },
      fetchFn,
    });

    expect(fetchFn).toHaveBeenCalledTimes(1);
    const [url, init] = fetchFn.mock.calls[0]!;
    expect(url).toBe(`${credentialsOrigin}/v1/credential-invitations`);
    expect(init).toMatchObject({
      method: "POST",
      credentials: "omit",
      redirect: "error",
      referrerPolicy: "no-referrer",
    });
    expect(init?.headers).toEqual({ accept: "application/json", "content-type": "application/json" });
    expect(init).not.toHaveProperty("referrer");
    expect(JSON.parse(String(init?.body))).toEqual({ request, admission, proof });
    expect(Object.keys(JSON.parse(String(init?.body))).sort()).toEqual(["admission", "proof", "request"]);
  });

  it("posts a v3 policy receipt to the existing delivery service without rewriting its root bindings", async () => {
    const request = Object.freeze({ returnLink: "https://share.example/s/inline#v=2&p=sealed-policy" });
    const admission = Object.freeze({ schema: "xyz.tinycloud.policy/delivery-admission/v0", policyId: "policy" });
    const proof = Object.freeze({ alg: "EdDSA", kid: "did:web:node.example#key", signature: "signature" });
    const fetchFn = vi.fn<typeof fetch>(async () => new Response(null, { status: 202 }));

    await requestAddressedDelivery({
      credentialsOrigin: "https://credentials.example",
      shareUrl: "https://share.example/s/inline#v=2&p=sealed-policy",
      deliveryAuthorization: { request, admission, proof },
      fetchFn,
    });

    const [url, init] = fetchFn.mock.calls[0]!;
    expect(url).toBe("https://credentials.example/v1/credential-invitations");
    expect(JSON.parse(String(init?.body))).toEqual({
      request,
      admission,
      proof,
    });
  });
});
