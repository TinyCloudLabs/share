import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { base64UrlDecode, base64UrlEncode, sha256, utf8 } from "../src/bytes.ts";
import { MAX_LINK_BODY_BYTES, REQUEST_BODY_CAP_BYTES, WORKERS_FREE_PLAN, type LinkType, type ServiceConfig } from "../src/config.ts";
import { runScheduled } from "../src/health.ts";
import { handleRequest, handleRequestWithReason, type ServiceDeps } from "../src/service.ts";
import { createSqliteAdapter, type Adapter } from "./support/adapters.ts";
import { AUDIENCE, filler, get, makeIssuer, signedCreate, signedDelete, take } from "./support/client.ts";

const NOW = Date.UTC(2026, 9, 24, 12, 0, 0);
const BASE_CONFIG: ServiceConfig = {
  audience: AUDIENCE,
  corsOrigins: ["https://share.tinycloud.xyz"],
  takeOrigins: [],
  addressSalt: "service-test-salt-0123456789",
  kill: { create: false, read: false, take: false, delete: false },
  clientAddressHeader: "CF-Connecting-IP",
};

describe("links API service", () => {
  let adapter: Adapter;
  let deps: ServiceDeps;
  let nowMs: number;
  let logs: string[];

  const build = (config: ServiceConfig = BASE_CONFIG): ServiceDeps => ({
    storage: adapter.storage(),
    config,
    usage: { plan: WORKERS_FREE_PLAN, tally: null, statsEveryMinutes: 1 },
    now: () => nowMs,
    log: (line) => logs.push(line),
  });
  const create = async (type: LinkType = "share", body?: Uint8Array) => {
    const issuer = makeIssuer();
    const response = await handleRequest(await signedCreate({ type, issuer, nowMs, ...(body ? { body } : {}) }), deps);
    const json = (await response.json()) as { id?: string; error?: string };
    return { issuer, response, id: json.id ?? "", json };
  };

  beforeAll(async () => {
    adapter = await createSqliteAdapter();
  });
  afterAll(async () => {
    await adapter.close();
  });
  beforeEach(async () => {
    await adapter.reset();
    nowMs = NOW;
    logs = [];
    deps = build();
  });

  describe("one body limit for every type", () => {
    it("derives the HTTP request cap from MAX_LINK_BODY_BYTES", () => {
      expect(MAX_LINK_BODY_BYTES).toBe(65_536);
      expect(REQUEST_BODY_CAP_BYTES).toBe(90_454);
    });

    it.each(["openkey-login", "courier", "share"] as const)("%s: 65,536 bytes is accepted and 65,537 is refused by the body check", async (type) => {
      const issuer = makeIssuer();
      const at = await handleRequestWithReason(await signedCreate({ type, issuer, body: filler(MAX_LINK_BODY_BYTES), nowMs }), deps);
      expect(at.response.status).toBe(201);
      const over = await handleRequestWithReason(await signedCreate({ type, issuer: makeIssuer(), body: filler(MAX_LINK_BODY_BYTES + 1), nowMs }), deps);
      expect(over.response.status).toBe(413);
      expect(await over.response.json()).toEqual({ error: "too_large" });
      expect(over.reason).toBe("body_over_cap");
    });

    it("cuts off an HTTP body over the derived cap before parsing it", async () => {
      const request = new Request(`${AUDIENCE}/v1/links`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "CF-Connecting-IP": "203.0.113.9" },
        body: "x".repeat(REQUEST_BODY_CAP_BYTES + 1),
      });
      const outcome = await handleRequestWithReason(request, deps);
      expect(outcome.response.status).toBe(413);
      expect(outcome.reason).toBe("request_too_large");
    });
  });

  describe("create, read, take and delete", () => {
    it("serves a share record as raw bytes with the signed record in X-Link-Record", async () => {
      const body = filler(300);
      const { response, id, issuer } = await create("share", body);
      expect(response.status).toBe(201);
      expect(id).toMatch(/^[a-z2-7]{26}$/);
      const read = await handleRequest(get(id.toUpperCase()), deps);
      expect(read.status).toBe(200);
      expect(new Uint8Array(await read.arrayBuffer())).toEqual(body);
      expect(read.headers.get("Content-Type")).toBe("application/octet-stream");
      expect(read.headers.get("Content-Disposition")).toBe('attachment; filename="link.bin"');
      expect(read.headers.get("X-Content-Type-Options")).toBe("nosniff");
      expect(read.headers.get("Content-Security-Policy")).toBe("default-src 'none'; sandbox");
      expect(read.headers.get("Cross-Origin-Resource-Policy")).toBe("same-site");
      expect(read.headers.get("Cache-Control")).toBe("no-store");
      expect(read.headers.get("Access-Control-Allow-Origin")).toBe("*");
      expect(read.headers.get("Access-Control-Expose-Headers")).toBe("X-Link-Record");
      expect(read.headers.get("Access-Control-Allow-Credentials")).toBeNull();
      expect(read.headers.get("Set-Cookie")).toBeNull();
      const record = JSON.parse(new TextDecoder().decode(base64UrlDecode(read.headers.get("X-Link-Record") ?? "") ?? new Uint8Array()));
      expect(record.header.issuer).toBe(issuer.did);
      expect(record.signature.algorithm).toBe("Ed25519");
      expect(Object.keys(record)).toEqual(["header", "signature"]);
    });

    it("openkey-login: GET never serves or consumes it; one POST take serves it once", async () => {
      const { id } = await create("openkey-login");
      expect((await handleRequest(get(id), deps)).status).toBe(404);
      expect((await handleRequest(take(id), deps)).status).toBe(200);
      expect((await handleRequest(take(id), deps)).status).toBe(404);
    });

    it("take of a share removes nothing", async () => {
      const { id } = await create("share");
      expect((await handleRequest(take(id), deps)).status).toBe(404);
      expect((await handleRequest(get(id), deps)).status).toBe(200);
    });

    it("only the issuer deletes; another valid issuer gets the same 404 as an unknown id", async () => {
      const { id, issuer } = await create("courier");
      const other = await handleRequest(await signedDelete({ issuer: makeIssuer(), id, nowMs }), deps);
      const unknown = await handleRequest(await signedDelete({ issuer: makeIssuer(), id: "a".repeat(26), nowMs }), deps);
      expect(other.status).toBe(404);
      expect(await other.text()).toBe(await unknown.text());
      expect((await handleRequest(get(id), deps)).status).toBe(200);
      expect((await handleRequest(await signedDelete({ issuer, id, nowMs }), deps)).status).toBe(204);
      expect((await handleRequest(get(id), deps)).status).toBe(404);
    });

    it("refuses a replayed signed create", async () => {
      const request = await signedCreate({ issuer: makeIssuer(), nowMs });
      expect((await handleRequest(request.clone(), deps)).status).toBe(201);
      const again = await handleRequest(request.clone(), deps);
      expect(again.status).toBe(409);
      expect(await again.json()).toEqual({ error: "replayed" });
    });

    it("works with no client address header (one shared bucket)", async () => {
      const request = await signedCreate({ issuer: makeIssuer(), nowMs });
      request.headers.delete("CF-Connecting-IP");
      expect((await handleRequest(request, deps)).status).toBe(201);
    });
  });

  describe("uniform not found", () => {
    it("unknown, expired, deleted, malformed and read-once-by-GET ids answer identically", async () => {
      const expired = await create("share");
      const deleted = await create("share");
      const once = await create("openkey-login");
      await handleRequest(await signedDelete({ issuer: deleted.issuer, id: deleted.id, nowMs }), deps);
      nowMs += 31 * 86_400_000;
      const ids = ["b".repeat(26), expired.id, deleted.id, "not-an-id", once.id];
      const seen = await Promise.all(
        ids.map(async (id, i) => {
          const response = await handleRequest(get(id, `203.0.113.${i + 1}`), deps);
          return { status: response.status, headers: [...response.headers].sort(), body: await response.text() };
        }),
      );
      for (const entry of seen) {
        expect(entry).toEqual(seen[0]);
      }
      expect(seen[0]?.status).toBe(404);
      expect(seen[0]?.body).toBe('{"error":"not_found"}');
    });
  });

  describe("browser surface", () => {
    it("refuses a create from an origin that is not first-party and sets no CORS headers", async () => {
      const response = await handleRequest(await signedCreate({ issuer: makeIssuer(), nowMs, headers: { Origin: "https://evil.example" } }), deps);
      expect(response.status).toBe(403);
      expect(response.headers.get("Access-Control-Allow-Origin")).toBeNull();
    });

    it("answers a first-party origin with that origin, Vary and no credentials", async () => {
      const response = await handleRequest(await signedCreate({ issuer: makeIssuer(), nowMs, headers: { Origin: "https://share.tinycloud.xyz" } }), deps);
      expect(response.status).toBe(201);
      expect(response.headers.get("Access-Control-Allow-Origin")).toBe("https://share.tinycloud.xyz");
      expect(response.headers.get("Vary")).toBe("Origin");
      expect(response.headers.get("Access-Control-Allow-Credentials")).toBeNull();
      expect(response.headers.get("Set-Cookie")).toBeNull();
    });

    it("preflight: listed origin gets Content-Type only (never Authorization); others are refused; take has none by default", async () => {
      const preflight = (path: string, origin: string) =>
        handleRequest(new Request(`${AUDIENCE}${path}`, { method: "OPTIONS", headers: { Origin: origin, "Access-Control-Request-Method": "POST" } }), deps);
      const listed = await preflight("/v1/links", "https://share.tinycloud.xyz");
      expect(listed.status).toBe(204);
      expect(listed.headers.get("Access-Control-Allow-Headers")).toBe("Content-Type");
      expect(listed.headers.get("Access-Control-Allow-Methods")).toBe("POST, OPTIONS");
      expect(listed.headers.get("Access-Control-Max-Age")).toBe("600");
      expect((await preflight("/v1/links", "https://evil.example")).headers.get("Access-Control-Allow-Origin")).toBeNull();
      expect((await preflight("/v1/links/aaaaaaaaaaaaaaaaaaaaaaaaaa/delete", "https://share.tinycloud.xyz")).status).toBe(204);
      expect((await preflight("/v1/links/aaaaaaaaaaaaaaaaaaaaaaaaaa/take", "https://share.tinycloud.xyz")).headers.get("Access-Control-Allow-Origin")).toBeNull();
    });

    it("requires a JSON content type on create and delete", async () => {
      const request = await signedCreate({ issuer: makeIssuer(), nowMs, headers: { "Content-Type": "text/plain" } });
      expect((await handleRequest(request, deps)).status).toBe(400);
    });
  });

  describe("operator controls", () => {
    it("kill switch answers 503 capacity with Retry-After", async () => {
      const killed = build({ ...BASE_CONFIG, kill: { ...BASE_CONFIG.kill, create: true } });
      const response = await handleRequest(await signedCreate({ issuer: makeIssuer(), nowMs }), killed);
      expect(response.status).toBe(503);
      expect(response.headers.get("Retry-After")).toBe("3600");
      expect(await response.json()).toEqual({ error: "capacity" });
    });

    it("a blocked issuer is refused on the next request; unblocking restores it", async () => {
      const issuer = makeIssuer();
      await deps.storage.setBlocked("issuer", issuer.did, "test", nowMs / 1000);
      expect((await handleRequest(await signedCreate({ issuer, nowMs }), deps)).status).toBe(403);
      await deps.storage.clearBlocked("issuer", issuer.did);
      expect((await handleRequest(await signedCreate({ issuer, nowMs }), deps)).status).toBe(201);
    });

    it("a revoked API key stops working on the next request", async () => {
      const secret = "d".repeat(43);
      const bearer = `tlk_apikey01_${secret}`;
      await deps.storage.addApiKey(
        { keyId: "apikey01", service: "openkey", allowedTypes: ["openkey-login"], secretSha256: base64UrlEncode(await sha256(utf8(secret))) },
        nowMs / 1000,
      );
      const make = async () => {
        const request = await signedCreate({ type: "openkey-login", issuer: makeIssuer(), nowMs });
        const parsed = JSON.parse(await request.text()) as { header: Record<string, unknown>; body: string };
        parsed.header["issuer"] = "service:openkey";
        return new Request(request.url, { method: "POST", headers: { "Content-Type": "application/json", Authorization: `Bearer ${bearer}` }, body: JSON.stringify({ header: parsed.header, body: parsed.body }) });
      };
      expect((await handleRequest(await make(), deps)).status).toBe(201);
      await deps.storage.revokeApiKey("apikey01", nowMs / 1000);
      expect((await handleRequest(await make(), deps)).status).toBe(401);
    });
  });

  describe("health line", () => {
    it("carries counts only and resets after each run", async () => {
      const { id } = await create("share");
      await handleRequest(get(id), deps);
      await handleRequest(get("c".repeat(26), "203.0.113.50"), deps);
      await runScheduled(deps);
      const first = JSON.parse(logs.at(-1) ?? "{}");
      expect(first.event).toBe("links.health");
      expect(first.creates.share).toBe(1);
      expect(first.reads).toEqual({ hit: 1, miss: 1 });
      expect(first.live.share.rows).toBe(1);
      expect(first.usage.requests.used).toBe(3);
      expect(logs.join("\n")).not.toContain(id);
      await runScheduled(deps);
      expect(JSON.parse(logs.at(-1) ?? "{}").creates.share).toBe(0);
    });
  });
});
