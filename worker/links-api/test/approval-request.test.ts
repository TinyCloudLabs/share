import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { randomBytes } from "node:crypto";
import { base64UrlDecode, base64UrlEncode, cidForBytes, sha256, utf8 } from "../src/bytes.ts";
import { MAX_LINK_BODY_BYTES, TYPE_CONFIG, type LinkType, type ServiceConfig } from "../src/config.ts";
import { handleRequest, type ServiceDeps } from "../src/service.ts";
import { DEFAULT_ADMISSION } from "../src/sql-storage.ts";
import { ADAPTER_FACTORIES, type Adapter } from "./support/adapters.ts";
import { AUDIENCE, filler, get, makeIssuer, sealBody, signedCreate, signedDelete, take } from "./support/client.ts";
import { makeRecord } from "./support/fixtures.ts";

const TYPE = "openkey-approval-request" as LinkType;
const NOW = Date.UTC(2026, 9, 28, 12);
const CONFIG: ServiceConfig = {
  audience: AUDIENCE,
  corsOrigins: ["https://share.tinycloud.xyz"],
  takeOrigins: [],
  addressSalt: "approval-request-local-synthetic-salt",
  kill: { create: false, read: false, take: false, delete: false },
  clientAddressHeader: "CF-Connecting-IP",
};

describe.each(ADAPTER_FACTORIES)("approval request: $name", ({ create }) => {
  let adapter: Adapter;
  let deps: ServiceDeps;
  let nowMs: number;

  beforeAll(async () => { adapter = await create(); });
  afterAll(async () => { await adapter.close(); });
  beforeEach(async () => {
    await adapter.reset();
    nowMs = NOW;
    deps = {
      storage: adapter.storage(), config: CONFIG,
      usage: { plan: null, tally: null, statsEveryMinutes: 1 },
      now: () => nowMs, log: () => {},
    };
  });

  it("preserves the sealed signed request across prefetch, repeated reads, and a refused take", async () => {
    const issuer = makeIssuer();
    const body = new Uint8Array(sealBody(JSON.stringify({ issuer: issuer.did, requestVersion: 1 }), randomBytes(32)));
    const request = await signedCreate({ type: TYPE, issuer, body, nowMs, lifeSeconds: 3_600 });
    const submitted = JSON.parse(await request.clone().text());
    const created = await handleRequest(request, deps);
    expect(created.status).toBe(201);
    const { id } = await created.json() as { id: string };
    expect(id).toMatch(/^[a-z2-7]{26}$/);
    for (const headers of [{ "Purpose": "prefetch", "Sec-Purpose": "prefetch" }, {}, {}]) {
      const read = await handleRequest(get(id, undefined, headers), deps);
      expect(read.status).toBe(200);
      expect(new Uint8Array(await read.arrayBuffer())).toEqual(body);
      expect(read.headers.get("Cache-Control")).toBe("no-store");
      const record = JSON.parse(new TextDecoder().decode(base64UrlDecode(read.headers.get("X-Link-Record")!)!));
      expect(record).toEqual({ header: submitted.header, signature: submitted.signature });
      expect(record.header.bodyCid).toBe(await cidForBytes(body));
    }
    expect((await handleRequest(take(id), deps)).status).toBe(404);
    const afterTake = await handleRequest(get(id), deps);
    expect(afterTake.status).toBe(200);
    expect(new Uint8Array(await afterTake.arrayBuffer())).toEqual(body);
  });

  it.each([120, 3_600, 86_400])("accepts an explicitly signed %i-second request lifetime", async (lifeSeconds) => {
    const response = await handleRequest(await signedCreate({ type: TYPE, issuer: makeIssuer(), nowMs, lifeSeconds }), deps);
    expect(response.status).toBe(201);
    expect((await response.json() as { expiresAt: string }).expiresAt).toBe(new Date(NOW + lifeSeconds * 1000).toISOString());
  });

  it.each([119, 86_401])("refuses a %i-second request lifetime without storing it", async (lifeSeconds) => {
    const response = await handleRequest(await signedCreate({ type: TYPE, issuer: makeIssuer(), nowMs, lifeSeconds }), deps);
    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: "invalid_request" });
    expect((await deps.storage.stats(nowMs / 1000))[TYPE]).toEqual({ rows: 0, bytes: 0 });
  });

  it("expires at the signed boundary even if a browser previously prefetched it, before any sweep", async () => {
    const created = await handleRequest(await signedCreate({ type: TYPE, issuer: makeIssuer(), nowMs, lifeSeconds: 3_600 }), deps);
    const { id } = await created.json() as { id: string };
    expect((await handleRequest(get(id, undefined, { Purpose: "prefetch" }), deps)).status).toBe(200);
    nowMs = NOW + 3_600_000 - 1;
    expect((await handleRequest(get(id), deps)).status).toBe(200);
    nowMs++;
    const expired = await handleRequest(get(id), deps);
    const unknown = await handleRequest(get("a".repeat(26)), deps);
    expect(expired.status).toBe(404);
    expect(await expired.text()).toBe(await unknown.text());
    expect(await adapter.driver.first("SELECT id FROM links WHERE id = ?", [id])).toEqual({ id });
    expect((await handleRequest(take(id), deps)).status).toBe(404);
  });

  it("rejects an already-expired request within the allowed issuance clock window", async () => {
    const response = await handleRequest(await signedCreate({ type: TYPE, issuer: makeIssuer(), nowMs: NOW - 120_000, lifeSeconds: 120 }), deps);
    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: "invalid_request" });
  });

  it("refuses service-mode approval requests even when the API key explicitly allows the type; existing service login still works", async () => {
    const secret = base64UrlEncode(randomBytes(32));
    const bearer = `tlk_tstkey01_${secret}`;
    await deps.storage.addApiKey({
      keyId: "tstkey01", service: "openkey", allowedTypes: [TYPE, "openkey-login"],
      secretSha256: base64UrlEncode(await sha256(utf8(secret))),
    }, nowMs / 1000);
    for (const type of [TYPE, "openkey-login"] as const) {
      const request = await signedCreate({ type, issuer: makeIssuer(), nowMs, lifeSeconds: 600 });
      const parsed = await request.json() as { header: Record<string, unknown>; body: string };
      parsed.header.issuer = "service:openkey";
      const response = await handleRequest(new Request(request.url, {
        method: "POST", headers: { "Content-Type": "application/json", Authorization: `Bearer ${bearer}` },
        body: JSON.stringify({ header: parsed.header, body: parsed.body }),
      }), deps);
      expect(response.status).toBe(type === TYPE ? 400 : 201);
    }
    expect((await deps.storage.stats(nowMs / 1000))[TYPE]).toEqual({ rows: 0, bytes: 0 });
  });

  it.each(["signature", "issuer", "body", "size", "audience", "extra-header", "nonce", "unsigned"] as const)(
    "refuses a changed %s instead of admitting an unauthenticated or altered request",
    async (field) => {
      const request = await signedCreate({ type: TYPE, issuer: makeIssuer(), nowMs, lifeSeconds: 3_600 });
      const parsed = await request.json() as {
        header: Record<string, unknown> & { size: number };
        body: string;
        signature?: { value: string };
      };
      switch (field) {
        case "signature": parsed.signature!.value = base64UrlEncode(randomBytes(64)); break;
        case "issuer": parsed.header.issuer = makeIssuer().did; break;
        case "body": parsed.body = base64UrlEncode(filler(parsed.header.size).fill(0x43)); break;
        case "size": parsed.header.size++; break;
        case "audience": parsed.header.audience = "https://openkey.tinycloud.xyz"; break;
        case "extra-header": parsed.header.requestVersion = 1; break;
        case "nonce": parsed.header.nonce = "invalid"; break;
        case "unsigned": delete parsed.signature; break;
      }
      const response = await handleRequest(new Request(request.url, {
        method: "POST", headers: request.headers, body: JSON.stringify(parsed),
      }), deps);
      expect(response.status).toBe(["signature", "issuer", "unsigned"].includes(field) ? 401 : 400);
      expect((await deps.storage.stats(nowMs / 1000))[TYPE]).toEqual({ rows: 0, bytes: 0 });
    },
  );

  it("refuses replay without changing the first immutable record", async () => {
    const request = await signedCreate({ type: TYPE, issuer: makeIssuer(), nowMs, lifeSeconds: 3_600 });
    const created = await handleRequest(request.clone(), deps);
    const { id } = await created.json() as { id: string };
    const original = await handleRequest(get(id), deps);
    const repeated = await handleRequest(request, deps);
    expect(repeated.status).toBe(409);
    expect(await repeated.json()).toEqual({ error: "replayed" });
    const after = await handleRequest(get(id), deps);
    expect(after.headers.get("X-Link-Record")).toBe(original.headers.get("X-Link-Record"));
    expect(await after.arrayBuffer()).toEqual(await original.arrayBuffer());
  });

  it("only the authenticated issuer can delete the request", async () => {
    const issuer = makeIssuer();
    const created = await handleRequest(await signedCreate({ type: TYPE, issuer, nowMs, lifeSeconds: 3_600 }), deps);
    const { id } = await created.json() as { id: string };
    expect((await handleRequest(await signedDelete({ issuer: makeIssuer(), id, nowMs }), deps)).status).toBe(404);
    expect((await handleRequest(get(id), deps)).status).toBe(200);
    expect((await handleRequest(await signedDelete({ issuer, id, nowMs }), deps)).status).toBe(204);
    expect((await handleRequest(get(id), deps)).status).toBe(404);
  });

  it("retains the generic origin and sealed-body cap checks", async () => {
    const foreign = await handleRequest(await signedCreate({
      type: TYPE, issuer: makeIssuer(), nowMs, lifeSeconds: 3_600, headers: { Origin: "https://evil.example" },
    }), deps);
    expect(foreign.status).toBe(403);
    expect(foreign.headers.get("Access-Control-Allow-Origin")).toBeNull();
    for (const size of [MAX_LINK_BODY_BYTES, MAX_LINK_BODY_BYTES + 1]) {
      const response = await handleRequest(await signedCreate({
        type: TYPE, issuer: makeIssuer(), nowMs, lifeSeconds: 3_600, body: filler(size),
      }), deps);
      expect(response.status).toBe(size === MAX_LINK_BODY_BYTES ? 201 : 413);
    }
  });

  it("retains the per-issuer create rate limit for the new type", async () => {
    const issuer = makeIssuer();
    for (let i = 0; i < 10; i++) {
      expect((await handleRequest(await signedCreate({ type: TYPE, issuer, nowMs, lifeSeconds: 3_600 }), deps)).status).toBe(201);
    }
    const response = await handleRequest(await signedCreate({ type: TYPE, issuer, nowMs, lifeSeconds: 3_600 }), deps);
    expect(response.status).toBe(429);
    expect(await response.json()).toEqual({ error: "rate_limited" });
  });

  it("applies atomic type admission without borrowing the existing login quota", async () => {
    const storage = adapter.storage({
      ...DEFAULT_ADMISSION, types: { ...TYPE_CONFIG, [TYPE]: { quotaRows: 1, quotaBytes: 64 } },
    });
    const now = NOW / 1000;
    const record = (type: LinkType, addressHash: string) => makeRecord({
      type, addressHash, issuedAt: now, expiresAt: now + 3_600,
    });
    expect(await storage.put(record(TYPE, "first"), now)).toBe("ok");
    expect(await storage.put(record(TYPE, "second"), now)).toBe("type_quota");
    expect(await storage.put(record("openkey-login", "third"), now)).toBe("ok");
    expect((await storage.stats(now))[TYPE]).toEqual({ rows: 1, bytes: 64 });
    expect((await storage.stats(now))["openkey-login"]).toEqual({ rows: 1, bytes: 64 });
  });
});
