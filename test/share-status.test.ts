import { describe, expect, it, vi } from "vitest";
import { availabilityTarget, checkShareAvailability, type ShareAvailabilityTarget } from "../src/email-share/share-status.js";

const NODE = "https://tee.node.tinycloud.xyz";
const target: ShareAvailabilityTarget = { nodeOrigin: NODE, rootCids: ["bafyPolicyRoot", "bafyEnforcementRoot"] };
const NOW = Date.parse("2026-10-20T12:00:00Z");

function status(rootCid: string, state: "active" | "revoked", freshUntil = "2030-01-01T00:00:00Z"): Response {
  return Response.json({ rootCid, state, checkpoint: { state, freshUntil } });
}

/** Answers each root's status request from `answers`, keyed by CID; anything else is a 404. */
function node(answers: Record<string, () => Response | Promise<Response>>) {
  return vi.fn<typeof fetch>(async (input) => {
    const cid = decodeURIComponent(new URL(String(input)).pathname.split("/").at(-1)!);
    return answers[cid]?.() ?? new Response("policy-root-missing", { status: 404 });
  });
}

const check = (fetchFn: typeof fetch, timeoutMs?: number) => checkShareAvailability(target, { fetch: fetchFn, now: () => NOW, ...(timeoutMs === undefined ? {} : { timeoutMs }) });

describe("share availability pre-check", () => {
  it("asks the node's public status route for each root with nothing identifying attached", async () => {
    const fetchFn = node({ bafyPolicyRoot: () => status("bafyPolicyRoot", "active"), bafyEnforcementRoot: () => status("bafyEnforcementRoot", "active") });
    expect(await check(fetchFn)).toBe("available");
    expect(fetchFn.mock.calls.map(([url]) => String(url)).sort()).toEqual([`${NODE}/policy/v3/status/bafyEnforcementRoot`, `${NODE}/policy/v3/status/bafyPolicyRoot`]);
    for (const [, init] of fetchFn.mock.calls) {
      expect(init).toMatchObject({ method: "GET", credentials: "omit", cache: "no-store", referrerPolicy: "no-referrer", redirect: "error" });
      expect(Object.keys(init!.headers as object)).toEqual(["accept"]);
    }
  });

  it.each([
    ["policy root", { bafyPolicyRoot: () => status("bafyPolicyRoot", "revoked"), bafyEnforcementRoot: () => status("bafyEnforcementRoot", "active") }],
    ["enforcement root", { bafyPolicyRoot: () => status("bafyPolicyRoot", "active"), bafyEnforcementRoot: () => status("bafyEnforcementRoot", "revoked") }],
  ])("reports revoked when the %s is revoked", async (_name, answers) => {
    expect(await check(node(answers))).toBe("revoked");
  });

  it("reports revoked for a root revoked through the generic route, whose checkpoint still reads active", async () => {
    const generic = () => Response.json({ rootCid: "bafyPolicyRoot", state: "revoked", checkpoint: { state: "active", freshUntil: "2030-01-01T00:00:00Z" } });
    expect(await check(node({ bafyPolicyRoot: generic }))).toBe("revoked");
  });

  it("reports expired when an active root's own expiry has passed, and revoked wins over expired", async () => {
    const expired = (cid: string) => () => status(cid, "active", "2026-10-20T11:59:59Z");
    expect(await check(node({ bafyPolicyRoot: expired("bafyPolicyRoot"), bafyEnforcementRoot: expired("bafyEnforcementRoot") }))).toBe("expired");
    expect(await check(node({ bafyPolicyRoot: expired("bafyPolicyRoot"), bafyEnforcementRoot: () => status("bafyEnforcementRoot", "revoked") }))).toBe("revoked");
  });

  it("treats an unknown root (404) as available", async () => {
    expect(await check(node({}))).toBe("available");
  });

  it.each([
    ["a network error", () => { throw new TypeError("Failed to fetch"); }],
    ["a CORS refusal", () => { throw new TypeError("NetworkError when attempting to fetch resource."); }],
    ["a 500", () => new Response("boom", { status: 500 })],
    ["a 503", () => new Response("busy", { status: 503 })],
    ["a 403", () => new Response("root-status-invalid", { status: 403 })],
    ["a body that is not JSON", () => new Response("<html>", { status: 200 })],
    ["a JSON body of the wrong shape", () => Response.json(["revoked"])],
    ["a status for a different root", () => Response.json({ rootCid: "bafyOther", state: "revoked", checkpoint: { state: "revoked", freshUntil: "2030-01-01T00:00:00Z" } })],
    ["an unknown state", () => Response.json({ rootCid: "bafyPolicyRoot", state: "paused", checkpoint: { state: "paused", freshUntil: "2020-01-01T00:00:00Z" } })],
    ["an unreadable expiry", () => Response.json({ rootCid: "bafyPolicyRoot", state: "active", checkpoint: { state: "active", freshUntil: "soon" } })],
  ])("fails open on %s", async (_name, answer) => {
    expect(await check(node({ bafyPolicyRoot: answer, bafyEnforcementRoot: answer }))).toBe("available");
  });

  it("lets a root that cannot be read say nothing while a definite answer for the other still counts", async () => {
    // A failing root says nothing; a definite answer from the other still counts.
    const fetchFn = node({ bafyPolicyRoot: () => { throw new TypeError("Failed to fetch"); }, bafyEnforcementRoot: () => status("bafyEnforcementRoot", "revoked") });
    expect(await check(fetchFn)).toBe("revoked");
  });

  it("gives up on a node that does not answer in time and lets the normal flow run", async () => {
    const hang = (_input: RequestInfo | URL, init?: RequestInit) => new Promise<Response>((_resolve, reject) => init?.signal?.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError"))));
    const started = Date.now();
    expect(await check(hang as typeof fetch, 25)).toBe("available");
    expect(Date.now() - started).toBeLessThan(1_000);
  });
});

describe("availabilityTarget", () => {
  const envelope = { version: 3, target: { origin: NODE, nodeAudience: "did:key:z6MkNode", spaceId: "space" }, policyRoot: { cid: "bafyPolicyRoot" }, enforcementRoot: { cid: "bafyEnforcementRoot" } };

  it("reads the node origin and both roots from a Policy/v3 invitation", () => {
    expect(availabilityTarget(envelope)).toEqual({ nodeOrigin: NODE, rootCids: ["bafyPolicyRoot", "bafyEnforcementRoot"] });
  });

  it.each([
    ["not an object", "x"],
    ["no target", { ...envelope, target: undefined }],
    ["a non-canonical origin", { ...envelope, target: { origin: `${NODE}/path` } }],
    ["an unparsable origin", { ...envelope, target: { origin: "not a url" } }],
    ["no roots", { ...envelope, policyRoot: undefined, enforcementRoot: undefined }],
  ])("skips the check for %s", (_name, value) => {
    expect(availabilityTarget(value)).toBeUndefined();
  });
});
