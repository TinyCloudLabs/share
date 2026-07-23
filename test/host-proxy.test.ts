import { describe, expect, it } from "vitest";
import { sanitizeUpstreamRequest, sanitizeUpstreamResponse } from "../src/host/upstream.js";

describe("production upstream proxy boundary", () => {
  it("forwards only protocol headers and regenerates origin", () => {
    const incoming = new Headers({
      accept: "application/json",
      "content-type": "application/json; charset=utf-8",
      cookie: "share_session=attacker-secret",
      authorization: "Bearer attacker",
      host: "evil.example",
      "x-forwarded-for": "203.0.113.7",
      "x-real-ip": "203.0.113.7",
      connection: "keep-alive",
      "content-length": "12",
      "idempotency-key": "request-key",
    });
    const forwarded = sanitizeUpstreamRequest("/v1/share-email/invitations", "POST", incoming, 2, "https://share.tinycloud.xyz");
    expect(forwarded.get("accept")).toBe("application/json");
    expect(forwarded.get("content-type")).toBe("application/json; charset=utf-8");
    expect(forwarded.get("idempotency-key")).toBe("request-key");
    expect(forwarded.get("origin")).toBe("https://share.tinycloud.xyz");
    for (const name of ["cookie", "authorization", "host", "x-forwarded-for", "x-real-ip", "connection", "content-length", "transfer-encoding"]) expect(forwarded.has(name)).toBe(false);
  });

  it("strips upstream cookies, redirects, and security-header injection", () => {
    const upstream = new Response(JSON.stringify({ status: "accepted" }), { status: 200, headers: {
      "content-type": "application/json",
      "set-cookie": "share_session=upstream-secret",
      "content-security-policy": "default-src *",
      "x-frame-options": "ALLOWALL",
      "cache-control": "private",
      "content-length": "22",
      "transfer-encoding": "chunked",
      "connection": "close",
    }});
    const filtered = sanitizeUpstreamResponse("/v1/share-email/invitations", "POST", upstream);
    expect(filtered.headers.get("content-type")).toContain("application/json");
    for (const name of ["set-cookie", "content-security-policy", "x-frame-options", "cache-control", "referrer-policy", "x-content-type-options", "content-length", "transfer-encoding", "connection"]) expect(filtered.headers.has(name)).toBe(false);
    expect(() => sanitizeUpstreamResponse("/v1/share-email/invitations", "POST", new Response(null, { status: 302, headers: { location: "https://evil.example" } }))).toThrow(/redirect/);
  });

  it.each([
    ["GET", "/v1/share-email/invitations", "application/json"],
    ["POST", "/share/v1/read", "text/plain"],
    ["POST", "/registry/blobs", "application/json"],
  ])("fails closed for invalid method or content type (%s %s)", (method, path, contentType) => {
    expect(() => sanitizeUpstreamRequest(path, method, new Headers({ "content-type": contentType }), 1, "https://share.tinycloud.xyz")).toThrow();
  });

  it("fails closed before forwarding an oversized body", () => {
    expect(() => sanitizeUpstreamRequest("/share/v1/read", "POST", new Headers({ "content-type": "application/json" }), 128 * 1024 + 1, "https://share.tinycloud.xyz")).toThrow(/large/);
  });

  it.each([
    "/share/v1/invitations/authorize",
    "/share/v1/policy/challenges",
    "/share/v1/policy/session",
    "/share/v1/read",
  ])("allows the exact production Node route %s", (path) => {
    expect(() => sanitizeUpstreamRequest(path, "POST", new Headers({ "content-type": "application/json" }), 2, "https://share.tinycloud.xyz")).not.toThrow();
  });
});
