import { describe, expect, it } from "vitest";
import { handleRequest, handleScheduled } from "../src/app";
import { base64UrlEncode, cidForBytes, hashDeleteToken, newDeleteToken, newShareId } from "../src/encoding";
import type { Env } from "../src/d1";
import { insertLink } from "../src/store";
import { makeTestDb, type TestDb } from "./helpers/d1";

const NOW = Date.UTC(2026, 0, 1, 0, 0, 0);
const BASE = "https://share.tinycloud.xyz/api/share-links";
const TTL = 3_600_000;
const NOT_FOUND_BODY = '{"error":"not_found"}';
const GONE_BODY = '{"error":"gone"}';

function envFor(test: TestDb): Env {
  return { DB: test.db };
}

function createRequest(ip: string, body: unknown, url = BASE): Request {
  return new Request(url, {
    method: "POST",
    headers: { "CF-Connecting-IP": ip, "Content-Type": "application/json" },
    body: typeof body === "string" ? body : JSON.stringify(body),
  });
}

/** Seeds a live link directly: the create route no longer exists, but earlier links are still read and deleted here. */
async function create(
  test: TestDb,
  _ip = "198.51.100.1",
  nowMs = NOW,
  ttlMs = TTL,
): Promise<{ id: string; cid: string; deleteToken: string }> {
  const bytes = new Uint8Array(64).fill(9);
  const id = newShareId();
  const deleteToken = newDeleteToken();
  const cid = await cidForBytes(bytes);
  const outcome = await insertLink(test.db, {
    id, ciphertext: bytes, cid, expiresAtSeconds: Math.floor((nowMs + ttlMs) / 1000), deleteHash: await hashDeleteToken(deleteToken), nowSeconds: Math.floor(nowMs / 1000),
  });
  expect(outcome).toBe("ok");
  return { id, cid, deleteToken };
}

function getRequest(id: string, ip = "198.51.100.2"): Request {
  return new Request(`${BASE}/${id}`, { method: "GET", headers: { "CF-Connecting-IP": ip } });
}

function deleteRequest(id: string, token: string | null): Request {
  const headers: Record<string, string> = { "CF-Connecting-IP": "198.51.100.3" };
  if (token !== null) {
    headers.Authorization = `Bearer ${token}`;
  }
  return new Request(`${BASE}/${id}`, { method: "DELETE", headers });
}

describe("POST /api/share-links (retired: links are created through the links API)", () => {
  it("answers 410 gone with no other field, stores nothing, and sets no CORS headers", async () => {
    const test = makeTestDb();
    const response = await handleRequest(createRequest("198.51.100.1", { ciphertext: base64UrlEncode(new Uint8Array(64).fill(9)), expiresAt: new Date(NOW + TTL).toISOString() }), envFor(test), NOW);
    expect(response.status).toBe(410);
    expect(await response.text()).toBe(GONE_BODY);
    expect(response.headers.get("Content-Type")).toMatch(/application\/json/);
    expect(response.headers.get("Cache-Control")).toBe("no-store");
    expect(response.headers.get("Access-Control-Allow-Origin")).toBeNull();
    expect(test.raw.prepare("SELECT count(*) AS n FROM links").get()).toEqual({ n: 0 });
  });

  it("answers any body, and a query string, the same way", async () => {
    const test = makeTestDb();
    for (const [body, url] of [["{not json", BASE], ["", BASE], ["{}", `${BASE}?x=1`]] as const) {
      const response = await handleRequest(createRequest("198.51.100.5", body, url), envFor(test), NOW);
      expect(response.status).toBe(410);
      expect(await response.text()).toBe(GONE_BODY);
    }
  });

  it("does not answer a sibling path with 410", async () => {
    const test = makeTestDb();
    const response = await handleRequest(createRequest("198.51.100.6", "{}", `${BASE}X`), envFor(test), NOW);
    expect(response.status).toBe(404);
    expect(await response.text()).toBe(NOT_FOUND_BODY);
  });

  it("leaves reading and deleting an earlier link working", async () => {
    const test = makeTestDb();
    const created = await create(test);
    expect((await handleRequest(getRequest(created.id), envFor(test), NOW + 1000)).status).toBe(200);
    expect((await handleRequest(deleteRequest(created.id, created.deleteToken), envFor(test), NOW + 1000)).status).toBe(204);
  });
});

describe("GET /api/share-links/<id>", () => {
  it("returns the raw sealed bytes with the contract headers and no CORS headers", async () => {
    const test = makeTestDb();
    const created = await create(test);
    const response = await handleRequest(getRequest(created.id), envFor(test), NOW + 1000);
    expect(response.status).toBe(200);
    expect(response.headers.get("Content-Type")).toBe("application/octet-stream");
    expect(response.headers.get("X-Content-Type-Options")).toBe("nosniff");
    expect(response.headers.get("Content-Disposition")).toBe('attachment; filename="share.bin"');
    expect(response.headers.get("Content-Security-Policy")).toBe("default-src 'none'; sandbox");
    expect(response.headers.get("Cross-Origin-Resource-Policy")).toBe("same-origin");
    expect(response.headers.get("Cache-Control")).toBe("no-store");
    expect(response.headers.get("X-Share-Cid")).toBe(created.cid);
    expect(response.headers.get("X-Share-Expires")).toBe(new Date(NOW + TTL).toISOString());
    expect(response.headers.get("Access-Control-Allow-Origin")).toBeNull();
    expect(new Uint8Array(await response.arrayBuffer())).toEqual(new Uint8Array(64).fill(9));
  });

  it("accepts an uppercase id and resolves it to the same record", async () => {
    const test = makeTestDb();
    const created = await create(test);
    const response = await handleRequest(getRequest(created.id.toUpperCase()), envFor(test), NOW);
    expect(response.status).toBe(200);
  });

  it("returns an identical 404 for malformed, unknown, and expired ids", async () => {
    const test = makeTestDb();
    const expired = await create(test, "198.51.100.1", NOW);
    const probes = [getRequest("short"), getRequest("a".repeat(26)), getRequest(expired.id)];
    const readAfterExpiry = NOW + TTL + 1000;
    for (const probe of probes) {
      const response = await handleRequest(probe, envFor(test), readAfterExpiry);
      expect(response.status).toBe(404);
      expect(await response.text()).toBe(NOT_FOUND_BODY);
    }
  });
});

describe("DELETE /api/share-links/<id>", () => {
  it("returns 204 for the right token and the record is gone afterwards", async () => {
    const test = makeTestDb();
    const created = await create(test);
    const removed = await handleRequest(deleteRequest(created.id, created.deleteToken), envFor(test), NOW + 1000);
    expect(removed.status).toBe(204);
    const after = await handleRequest(getRequest(created.id), envFor(test), NOW + 2000);
    expect(after.status).toBe(404);
  });

  it("keeps a tombstone with empty ciphertext and a deleted_at timestamp", async () => {
    const test = makeTestDb();
    const created = await create(test);
    await handleRequest(deleteRequest(created.id, created.deleteToken), envFor(test), NOW + 1000);
    const row = test.raw
      .prepare("SELECT length(ciphertext) AS len, size, deleted_at FROM links WHERE id = ?")
      .get(created.id) as { len: number; size: number; deleted_at: number | null };
    expect(row.len).toBe(0);
    expect(row.size).toBe(0);
    expect(row.deleted_at).toBe(Math.floor((NOW + 1000) / 1000));
  });

  it("returns the same 404 for a wrong token, a missing header, and a second delete", async () => {
    const test = makeTestDb();
    const created = await create(test);
    const wrong = await handleRequest(deleteRequest(created.id, "A".repeat(43)), envFor(test), NOW + 1000);
    const missing = await handleRequest(deleteRequest(created.id, null), envFor(test), NOW + 1000);
    await handleRequest(deleteRequest(created.id, created.deleteToken), envFor(test), NOW + 1000);
    const again = await handleRequest(deleteRequest(created.id, created.deleteToken), envFor(test), NOW + 1000);
    for (const response of [wrong, missing, again]) {
      expect(response.status).toBe(404);
      expect(await response.text()).toBe(NOT_FOUND_BODY);
    }
  });

  it("rate-limits deletes to 120 per minute per client", async () => {
    const test = makeTestDb();
    const probe = "a".repeat(26);
    for (let i = 0; i < 120; i++) {
      await handleRequest(deleteRequest(probe, null), envFor(test), NOW);
    }
    const response = await handleRequest(deleteRequest(probe, null), envFor(test), NOW);
    expect(response.status).toBe(429);
    expect(await response.json()).toEqual({ error: "rate_limited" });
  });
});

describe("scheduled cleanup", () => {
  it("removes expired rows and keeps live rows", async () => {
    const test = makeTestDb();
    const live = await create(test, "198.51.100.1", NOW, TTL);
    await create(test, "198.51.100.4", NOW, 120_000);
    await handleScheduled(envFor(test), NOW + 200_000);
    const remaining = test.raw.prepare("SELECT id FROM links").all() as { id: string }[];
    expect(remaining.map((row) => row.id)).toEqual([live.id]);
  });
});

describe("query strings and sibling paths", () => {
  it("answers the collection path with a query string as the uniform 404 without CORS", async () => {
    const test = makeTestDb();
    const request = new Request(`${BASE}?list`, { method: "GET", headers: { "CF-Connecting-IP": "198.51.100.40" } });
    const response = await handleRequest(request, envFor(test), NOW);
    expect(response.status).toBe(404);
    expect(response.headers.get("Content-Type")).toMatch(/application\/json/);
    expect(response.headers.get("Access-Control-Allow-Origin")).toBeNull();
    expect(await response.text()).toBe(NOT_FOUND_BODY);
  });

  it("answers a trailing slash with a query string as the uniform 404 without CORS", async () => {
    const test = makeTestDb();
    const request = new Request(`${BASE}/?list`, { method: "GET", headers: { "CF-Connecting-IP": "198.51.100.41" } });
    const response = await handleRequest(request, envFor(test), NOW);
    expect(response.status).toBe(404);
    expect(response.headers.get("Access-Control-Allow-Origin")).toBeNull();
    expect(await response.text()).toBe(NOT_FOUND_BODY);
  });

  it("answers a sibling path as the uniform 404 without CORS, with or without a query string", async () => {
    const test = makeTestDb();
    for (const url of [`${BASE}X`, `${BASE}X?list`]) {
      const request = new Request(url, { method: "GET", headers: { "CF-Connecting-IP": "198.51.100.42" } });
      const response = await handleRequest(request, envFor(test), NOW);
      expect(response.status).toBe(404);
      expect(response.headers.get("Access-Control-Allow-Origin")).toBeNull();
      expect(await response.text()).toBe(NOT_FOUND_BODY);
    }
  });
});
