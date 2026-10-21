// @vitest-environment node
import { describe, expect, it } from "vitest";
import vectorsJson from "./fixtures/shortlink-vectors.json";
import { setTimeout as sleep } from "node:timers/promises";
import { createShortLink, deleteShortLink, ShortLinkError } from "../src/short-links/client.js";

interface Vector {
  readonly inline: string;
  readonly id: string;
  readonly ciphertextB64Url: string;
  readonly cid: string;
  readonly k: string;
  readonly short: string;
}

const vector = (vectorsJson as readonly Vector[])[0]!;
const EXPIRES_AT = "2030-01-01T00:00:00.000Z";

interface Call {
  readonly url: string;
  readonly init: RequestInit;
}

function fetchReturning(response: Response | (() => Promise<Response>)): { fetchFn: typeof fetch; calls: Call[] } {
  const calls: Call[] = [];
  const fetchFn = (async (url: string, init: RequestInit) => {
    calls.push({ url, init });
    return typeof response === "function" ? response() : response.clone();
  }) as typeof fetch;
  return { fetchFn, calls };
}

function jsonResponse(status: number, body?: unknown): Response {
  return new Response(body === undefined ? null : JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

async function failureOf(promise: Promise<unknown>): Promise<string> {
  try {
    await promise;
  } catch (error) {
    if (error instanceof ShortLinkError) return error.reason;
    throw error;
  }
  throw new Error("expected a ShortLinkError");
}

describe("createShortLink", () => {
  it("sends only the sealed bytes and expiry, same-origin with credentials omitted", async () => {
    const { fetchFn, calls } = fetchReturning(jsonResponse(201, { id: vector.id, cid: vector.cid, deleteToken: "tok" }));

    await createShortLink({ ciphertext: vector.ciphertextB64Url, expiresAt: EXPIRES_AT }, { fetchFn });

    expect(calls).toHaveLength(1);
    expect(calls[0]!.url).toBe("/api/share-links");
    expect(calls[0]!.init.method).toBe("POST");
    expect(calls[0]!.init.credentials).toBe("omit");
    expect(JSON.parse(String(calls[0]!.init.body))).toEqual({ ciphertext: vector.ciphertextB64Url, expiresAt: EXPIRES_AT });
  });

  it("never sends the decryption key in the body, headers, or URL", async () => {
    const { fetchFn, calls } = fetchReturning(jsonResponse(201, { id: vector.id, cid: vector.cid, deleteToken: "tok" }));

    await createShortLink({ ciphertext: vector.ciphertextB64Url, expiresAt: EXPIRES_AT }, { fetchFn });

    const sent = calls[0]!;
    expect(String(sent.init.body)).not.toContain(vector.k);
    expect(JSON.stringify(sent.init.headers)).not.toContain(vector.k);
    expect(sent.url).not.toContain(vector.k);
    expect(String(sent.init.body)).not.toContain(vector.cid);
    expect(JSON.stringify(sent.init.headers)).not.toContain(vector.cid);
  });

  it("returns the id, cid, and delete token from a 201", async () => {
    const { fetchFn } = fetchReturning(jsonResponse(201, { id: vector.id, cid: vector.cid, deleteToken: "tok" }));

    await expect(createShortLink({ ciphertext: vector.ciphertextB64Url, expiresAt: EXPIRES_AT }, { fetchFn })).resolves.toEqual({
      id: vector.id,
      cid: vector.cid,
      deleteToken: "tok",
    });
  });

  it.each([
    [400, "rejected"],
    [429, "rate_limited"],
    [503, "capacity"],
    [500, "server"],
  ] as const)("maps HTTP %i to %s", async (status, reason) => {
    const { fetchFn } = fetchReturning(jsonResponse(status, { error: "x" }));

    expect(await failureOf(createShortLink({ ciphertext: vector.ciphertextB64Url, expiresAt: EXPIRES_AT }, { fetchFn }))).toBe(reason);
  });

  it("rejects a 201 whose id is not a 26-character base32 id", async () => {
    const { fetchFn } = fetchReturning(jsonResponse(201, { id: "NOT-A-VALID-ID", cid: vector.cid, deleteToken: "tok" }));

    expect(await failureOf(createShortLink({ ciphertext: vector.ciphertextB64Url, expiresAt: EXPIRES_AT }, { fetchFn }))).toBe("invalid_response");
  });

  it("rejects a 201 with no delete token, since revoke could never delete the link", async () => {
    const { fetchFn } = fetchReturning(jsonResponse(201, { id: vector.id, cid: vector.cid, deleteToken: "" }));

    expect(await failureOf(createShortLink({ ciphertext: vector.ciphertextB64Url, expiresAt: EXPIRES_AT }, { fetchFn }))).toBe("invalid_response");
  });

  it("maps a rejected fetch to network", async () => {
    const { fetchFn } = fetchReturning(() => Promise.reject(new TypeError("offline")));

    expect(await failureOf(createShortLink({ ciphertext: vector.ciphertextB64Url, expiresAt: EXPIRES_AT }, { fetchFn }))).toBe("network");
  });

  it("maps a request that outlives the timeout to timeout", async () => {
    const fetchFn = (async (_url: string, init: RequestInit) => {
      await sleep(60_000, undefined, { signal: init.signal ?? undefined });
      return new Response(null, { status: 201 });
    }) as typeof fetch;

    expect(
      await failureOf(createShortLink({ ciphertext: vector.ciphertextB64Url, expiresAt: EXPIRES_AT }, { fetchFn, timeoutMs: 5 })),
    ).toBe("timeout");
  });
});

describe("deleteShortLink", () => {
  it("sends the delete token as a bearer header to the id's path", async () => {
    const { fetchFn, calls } = fetchReturning(new Response(null, { status: 204 }));

    await deleteShortLink(vector.id, "tok", { fetchFn });

    expect(calls[0]!.url).toBe(`/api/share-links/${vector.id}`);
    expect(calls[0]!.init.method).toBe("DELETE");
    expect(new Headers(calls[0]!.init.headers).get("authorization")).toBe("Bearer tok");
  });

  it("treats 204 as deleted", async () => {
    const { fetchFn } = fetchReturning(new Response(null, { status: 204 }));

    await expect(deleteShortLink(vector.id, "tok", { fetchFn })).resolves.toBeUndefined();
  });

  it("throws on 404 so the caller keeps its record, since a wrong token leaves the link live", async () => {
    const { fetchFn } = fetchReturning(new Response(null, { status: 404 }));

    await expect(deleteShortLink(vector.id, "tok", { fetchFn })).rejects.toMatchObject({ reason: "rejected" });
  });

  it("reports a server error so the caller can keep the record for retry", async () => {
    const { fetchFn } = fetchReturning(new Response(null, { status: 500 }));

    expect(await failureOf(deleteShortLink(vector.id, "tok", { fetchFn }))).toBe("server");
  });

  it("rejects a malformed id before sending anything", async () => {
    const { fetchFn, calls } = fetchReturning(new Response(null, { status: 204 }));

    expect(await failureOf(deleteShortLink("../etc", "tok", { fetchFn }))).toBe("rejected");
    expect(calls).toHaveLength(0);
  });
});
