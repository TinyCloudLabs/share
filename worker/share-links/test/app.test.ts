import { describe, expect, it } from "vitest";
import { handleRequest, handleScheduled } from "../src/app";
import { base64UrlEncode } from "../src/encoding";
import type { Env } from "../src/d1";
import { makeTestDb, type TestDb } from "./helpers/d1";

const NOW = Date.UTC(2026, 0, 1, 0, 0, 0);
const BASE = "https://share.tinycloud.xyz/api/share-links";
const TTL = 3_600_000;
const NOT_FOUND_BODY = '{"error":"not_found"}';

function envFor(test: TestDb): Env {
  return { DB: test.db };
}

function ciphertext(length = 64): string {
  return base64UrlEncode(new Uint8Array(length).fill(9));
}

function createRequest(ip: string, body: unknown): Request {
  return new Request(BASE, {
    method: "POST",
    headers: { "CF-Connecting-IP": ip, "Content-Type": "application/json" },
    body: typeof body === "string" ? body : JSON.stringify(body),
  });
}

function validBody(ttlMs = TTL, nowMs = NOW): { ciphertext: string; expiresAt: string } {
  return { ciphertext: ciphertext(), expiresAt: new Date(nowMs + ttlMs).toISOString() };
}

async function create(
  test: TestDb,
  ip = "198.51.100.1",
  nowMs = NOW,
  body = validBody(TTL, nowMs),
): Promise<{ id: string; cid: string; deleteToken: string }> {
  const response = await handleRequest(createRequest(ip, body), envFor(test), nowMs);
  expect(response.status).toBe(201);
  return (await response.json()) as { id: string; cid: string; deleteToken: string };
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

describe("POST /api/share-links", () => {
  it("returns 201 with id, CID, and delete token, and no-store caching", async () => {
    const test = makeTestDb();
    const response = await handleRequest(createRequest("198.51.100.1", validBody()), envFor(test), NOW);
    expect(response.status).toBe(201);
    expect(response.headers.get("Cache-Control")).toBe("no-store");
    const body = (await response.json()) as { id: string; cid: string; deleteToken: string };
    expect(body.id).toMatch(/^[a-z2-7]{26}$/);
    expect(body.cid).toMatch(/^bafkrei[a-z2-7]{52}$/);
    expect(body.deleteToken).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });

  it("stores only the hash of the delete token, not the token", async () => {
    const test = makeTestDb();
    const created = await create(test);
    const row = test.raw.prepare("SELECT delete_hash FROM links WHERE id = ?").get(created.id) as { delete_hash: string };
    expect(row.delete_hash).not.toBe(created.deleteToken);
    expect(row.delete_hash).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });

  it("answers any invalid body with the uniform 400", async () => {
    const test = makeTestDb();
    const response = await handleRequest(createRequest("198.51.100.1", "{not json"), envFor(test), NOW);
    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: "invalid" });
  });

  it("rate-limits creates to 10 per minute per client", async () => {
    const test = makeTestDb();
    for (let i = 0; i < 10; i++) {
      await create(test, "198.51.100.9");
    }
    const response = await handleRequest(createRequest("198.51.100.9", validBody()), envFor(test), NOW);
    expect(response.status).toBe(429);
    expect(await response.json()).toEqual({ error: "rate_limited" });
    expect(Number(response.headers.get("Retry-After"))).toBeGreaterThanOrEqual(1);
  });

  it("returns 503 capacity when the live-byte cap would be exceeded", async () => {
    const test = makeTestDb();
    test.raw
      .prepare(
        "INSERT INTO links (id, ciphertext, cid, expires_at, delete_hash, size, created_at, deleted_at) VALUES (?, x'', ?, ?, ?, ?, ?, NULL)",
      )
      .run(
        "aaaaaaaaaaaaaaaaaaaaaaaaaa",
        "bafkreiexisting",
        Math.floor(NOW / 1000) + 3600,
        "h",
        2 * 1024 * 1024 * 1024 - 10,
        Math.floor(NOW / 1000),
      );
    const response = await handleRequest(createRequest("198.51.100.20", validBody()), envFor(test), NOW);
    expect(response.status).toBe(503);
    expect(await response.json()).toEqual({ error: "capacity" });
    expect(response.headers.get("Retry-After")).toBe("3600");
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
});

describe("scheduled cleanup", () => {
  it("removes expired rows and keeps live rows", async () => {
    const test = makeTestDb();
    const live = await create(test, "198.51.100.1", NOW, validBody(TTL, NOW));
    await create(test, "198.51.100.4", NOW, validBody(120_000, NOW));
    await handleScheduled(envFor(test), NOW + 200_000);
    const remaining = test.raw.prepare("SELECT id FROM links").all() as { id: string }[];
    expect(remaining.map((row) => row.id)).toEqual([live.id]);
  });
});
