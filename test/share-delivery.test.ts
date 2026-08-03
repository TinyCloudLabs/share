import { describe, expect, it, vi } from "vitest";
import { requestAddressedDelivery } from "../src/share/delivery.js";

describe("addressed delivery boundary", () => {
  it("posts the unchanged Node receipt only to OpenCredentials", async () => {
    const credentialsOrigin = "https://credentials.example";
    const workerOrigin = "https://worker.example";
    const authorization = Object.freeze({ type: "TinyCloudShareDeliveryAuthorization", version: 2, jti: "test-jti" });
    const proof = Object.freeze({ alg: "EdDSA", kid: "did:web:node.example#key", signature: "test-signature" });
    const shareUrl = "share-url-with-private-fragment";
    const fetchFn = vi.fn<typeof fetch>(async () => new Response(null, { status: 202 }));

    await requestAddressedDelivery({
      credentialsOrigin,
      shareUrl,
      deliveryAuthorization: { authorization, proof },
      fetchFn,
    });

    expect(fetchFn).toHaveBeenCalledTimes(1);
    const [url, init] = fetchFn.mock.calls[0]!;
    expect(url).toBe(`${credentialsOrigin}/share/v2`);
    expect(String(url)).not.toContain(workerOrigin);
    expect(init).toMatchObject({
      method: "POST",
      credentials: "omit",
      redirect: "error",
      referrerPolicy: "no-referrer",
    });
    expect(init?.headers).toEqual({ accept: "application/json", "content-type": "application/json" });
    expect(init).not.toHaveProperty("referrer");
    expect(JSON.parse(String(init?.body))).toEqual({ authorization, proof, shareUrl });
    expect(Object.keys(JSON.parse(String(init?.body))).sort()).toEqual(["authorization", "proof", "shareUrl"]);
  });
});
