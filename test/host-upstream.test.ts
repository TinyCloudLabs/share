import { describe, expect, it } from "vitest";
import { assertSafeUpstreamQuery, sanitizeUpstreamRequest, sanitizeUpstreamResponse, upstreamForPath, upstreamPathFor } from "../src/host/upstream.js";
import { validateTrustBundle } from "../src/host/trust-bundle.js";
import { toBase64Url } from "@tinycloud/share-envelope";

const bundle = validateTrustBundle({
  version: "tinycloud.share-email-trust-bundle/v1",
  shareOrigin: "https://share.tinycloud.xyz",
  returnOrigin: "https://share.tinycloud.xyz",
  registryOrigin: "https://registry.tinycloud.xyz",
  credentialsOrigin: "https://witness.credentials.org",
  nodeOrigin: "https://node.tinycloud.xyz",
  nodeAudience: "did:web:node.tinycloud.xyz",
  nodeInvitationKid: "did:web:node.tinycloud.xyz#invitation-key-1",
  nodeInvitationPublicKey: toBase64Url(new Uint8Array(32).fill(3)),
  nodeKeyVersion: 1,
  nodeEnabled: true,
  issuerDid: "did:web:issuer.credentials.org",
  issuerVct: "opencredentials.email/v1",
  issuerKid: "did:web:issuer.credentials.org#email-signing-key-1",
  issuerPublicKey: toBase64Url(new Uint8Array(32).fill(4)),
  issuerKeyVersion: 1,
  issuerEnabled: true,
});

describe("native Node Share forwarding", () => {
  it.each(["/delegate", "/invoke"])("forwards %s with the native authorization and CAS headers", (path) => {
    expect(upstreamForPath(bundle, path, {})).toEqual({ service: "node", origin: bundle.public.nodeOrigin });
    const headers = sanitizeUpstreamRequest(path, "POST", new Headers({ authorization: "Bearer opaque", "content-type": "application/json", etag: '"old"', "if-match": '"old"', "x-tinycloud-cursor": "cursor" }), 2, bundle.public.shareOrigin);
    expect(headers.get("authorization")).toBe("Bearer opaque");
    expect(headers.get("if-match")).toBe('"old"');
    expect(headers.get("x-tinycloud-cursor")).toBe("cursor");
    expect(headers.get("cookie")).toBeNull();
    expect(sanitizeUpstreamResponse(path, "POST", new Response("{}", { headers: { "content-type": "application/json", etag: '"new"', "set-cookie": "secret" } })).headers.get("etag")).toBe('"new"');
  });

  it("rejects credential-bearing query strings and unsupported native methods", () => {
    expect(() => assertSafeUpstreamQuery("/invoke", "?token=secret")).toThrow();
    expect(() => assertSafeUpstreamQuery("/invoke", "?email=alice@example.com")).toThrow();
    expect(() => sanitizeUpstreamRequest("/invoke", "GET", new Headers(), 0, bundle.public.shareOrigin)).toThrow();
  });

  it("maps the same-origin raw artifact route to the registry raw contract", () => {
    const path = "/s/bafkreigh2akiscaildc3yqf3v2f5f6f7f8f9g0h1i2j3k4l5m6n7o8p9/raw";
    expect(upstreamForPath(bundle, path, {})).toEqual({ service: "registry", origin: bundle.public.registryOrigin });
    expect(upstreamPathFor(path)).toBe("/ipfs/bafkreigh2akiscaildc3yqf3v2f5f6f7f8f9g0h1i2j3k4l5m6n7o8p9?format=raw");
    const headers = sanitizeUpstreamRequest(path, "GET", new Headers({ accept: "application/vnd.ipld.raw" }), 0, bundle.public.shareOrigin);
    expect(headers.get("accept")).toBe("application/vnd.ipld.raw");
    expect(sanitizeUpstreamResponse(path, "GET", new Response(new Uint8Array([1]), { headers: { "content-type": "application/vnd.ipld.raw" } })).headers.get("content-type")).toBe("application/vnd.ipld.raw");
  });
});
