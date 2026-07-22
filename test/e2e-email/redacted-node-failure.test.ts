import { describe, expect, it } from "vitest";
import { captureFirstRedactedNodeFailure, redactedNodeFailure } from "./redacted-node-failure.ts";

describe("redacted Node failure diagnostics", () => {
  it("keeps only route, status, and an allowlisted exact error category", async () => {
    const response = new Response(JSON.stringify({ error: { code: "invalid_holder_proof" } }), { status: 403 });
    const failure = await captureFirstRedactedNodeFailure(undefined, "/share/v1/policy/session", response);

    expect(failure).toEqual({ route: "/share/v1/policy/session", status: 403, category: "invalid_holder_proof" });
    expect(Object.keys(failure ?? {}).sort()).toEqual(["category", "route", "status"]);
    expect(await response.text()).toContain("invalid_holder_proof");
  });

  it.each([
    ["unknown code", JSON.stringify({ error: { code: "secret-token" } })],
    ["extra top-level field", JSON.stringify({ error: { code: "policy_denied" }, secret: "credential" })],
    ["extra error field", JSON.stringify({ error: { code: "policy_denied", detail: "signature" } })],
    ["malformed JSON", "not-json with a private key"],
    ["oversized body", JSON.stringify({ error: { code: "policy_denied" }, padding: "x".repeat(4096) })],
  ])("redacts %s as unknown without retaining source text", async (_label, body) => {
    const failure = await redactedNodeFailure("/share/v1/read", new Response(body, { status: 403 }));
    expect(failure).toEqual({ route: "/share/v1/read", status: 403, category: "unknown" });
    expect(JSON.stringify(failure)).not.toContain("secret-token");
    expect(JSON.stringify(failure)).not.toContain("credential");
    expect(JSON.stringify(failure)).not.toContain("signature");
    expect(JSON.stringify(failure)).not.toContain("private key");
  });

  it("retains the first failure and leaves successful responses uncaptured", async () => {
    const first = { route: "/share/v1/policy/challenges", status: 403, category: "policy_denied" as const };
    const second = new Response(JSON.stringify({ error: { code: "read_denied" } }), { status: 403 });

    await expect(captureFirstRedactedNodeFailure(first, "/share/v1/read", second)).resolves.toBe(first);
    await expect(captureFirstRedactedNodeFailure(undefined, "/share/v1/read", new Response("ok", { status: 200 }))).resolves.toBeUndefined();
  });
});
