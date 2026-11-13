import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { base64UrlEncode, sha256, utf8 } from "../src/bytes.ts";
import { LIMITS, WORKERS_FREE_PLAN, type ServiceConfig } from "../src/config.ts";
import { addressHashes, handleRequestWithReason, rateKeys, type ServiceDeps } from "../src/service.ts";
import { ADAPTER_FACTORIES, type Adapter } from "./support/adapters.ts";
import { AUDIENCE, CLIENT_IP, makeIssuer, signedCreate } from "./support/client.ts";

const NOW = Date.UTC(2026, 9, 24, 12, 0, 0);
const DAY = 86_400;
const CONFIG: ServiceConfig = {
  audience: AUDIENCE,
  corsOrigins: [],
  takeOrigins: [],
  addressSalt: "daily-budget-salt-0123456789",
  kill: { create: false, read: false, take: false, delete: false },
  clientAddressHeader: "CF-Connecting-IP",
};

describe.each(ADAPTER_FACTORIES)("create daily budgets: $name", ({ create }) => {
  let adapter: Adapter;
  let deps: ServiceDeps;
  let nowMs: number;

  const send = async (request: Request) => {
    const outcome = await handleRequestWithReason(request, deps);
    return { status: outcome.response.status, reason: outcome.reason, retryAfter: outcome.response.headers.get("Retry-After") };
  };
  const verified = (ip: string | null = CLIENT_IP) => signedCreate({ issuer: makeIssuer(), nowMs, ip });
  /** Signed by one key under another key's issuer: refused after the address check. */
  const badSignature = (ip: string | null = CLIENT_IP) => signedCreate({ issuer: { ...makeIssuer(), signDigest: makeIssuer().signDigest }, nowMs, ip });
  const count = async (key: string, windowSeconds: number) =>
    (await adapter.driver.first<{ n: number }>("SELECT n FROM rl WHERE k = ?", [`${key}:${Math.floor(nowMs / 1000 / windowSeconds)}`]))?.n ?? 0;
  /** Sets a counter's value for the current window. */
  const seed = async (key: string, windowSeconds: number, n: number) => {
    const bucket = Math.floor(nowMs / 1000 / windowSeconds);
    await adapter.driver.run("INSERT INTO rl (k, n, exp) VALUES (?, ?, ?) ON CONFLICT(k) DO UPDATE SET n = excluded.n", [`${key}:${bucket}`, n, (bucket + 1) * windowSeconds]);
  };
  const rows = async () => (await adapter.driver.first<{ n: number }>("SELECT count(*) AS n FROM links", []))?.n ?? 0;
  const hashFor = async (ip: string | null = CLIENT_IP) => (await addressHashes(CONFIG, ip)).rateHash;
  const attemptsKey = async (ip?: string | null) => rateKeys.addressCreate(await hashFor(ip), DAY);
  const verifiedKey = async (ip?: string | null) => rateKeys.addressVerifiedCreate(await hashFor(ip));
  const ceilingKey = rateKeys.publicCreate();
  const SECRET = "d".repeat(43);
  const addKey = async () =>
    deps.storage.addApiKey(
      { keyId: "apikey01", service: "openkey", allowedTypes: ["openkey-login"], secretSha256: base64UrlEncode(await sha256(utf8(SECRET))) },
      nowMs / 1000,
    );
  /** A create by the approved key `apikey01`, or with `secret` in its place. */
  const serviceCreate = async (secret = SECRET) => {
    const request = await signedCreate({ type: "openkey-login", issuer: makeIssuer(), nowMs });
    const parsed = JSON.parse(await request.text()) as { header: Record<string, unknown>; body: string };
    parsed.header["issuer"] = "service:openkey";
    return new Request(request.url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "CF-Connecting-IP": CLIENT_IP, Authorization: `Bearer tlk_apikey01_${secret}` },
      body: JSON.stringify({ header: parsed.header, body: parsed.body }),
    });
  };
  /** Neither signed nor carrying a key: refused after the address check, before the signature check. */
  const noCredentials = async () => {
    const request = await verified();
    const parsed = JSON.parse(await request.text()) as { header: unknown; body: unknown };
    return new Request(request.url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "CF-Connecting-IP": CLIENT_IP },
      body: JSON.stringify({ header: parsed.header, body: parsed.body }),
    });
  };

  beforeAll(async () => {
    adapter = await create();
  });
  afterAll(async () => {
    await adapter.close();
  });
  beforeEach(async () => {
    await adapter.reset();
    nowMs = NOW;
    deps = { storage: adapter.storage(), config: CONFIG, usage: { plan: WORKERS_FREE_PLAN, tally: null, statsEveryMinutes: 1 }, now: () => nowMs, log: () => undefined };
  });

  it("keeps the limits this change does not touch", () => {
    expect(LIMITS.addressCreate).toEqual([
      { limit: 30, windowSeconds: 60 },
      { limit: 600, windowSeconds: DAY },
    ]);
    expect(LIMITS.addressVerifiedCreate).toEqual({ limit: 2_000, windowSeconds: DAY });
    expect(LIMITS.publicCreate).toEqual({ limit: 3_000, windowSeconds: DAY });
    // One address alone cannot spend the shared ceiling.
    expect(LIMITS.addressVerifiedCreate.limit).toBeLessThan(LIMITS.publicCreate.limit);
  });

  it("a refusal after the address check counts against the attempt budget, not the verified one", async () => {
    expect((await send(await badSignature())).reason).toBe("bad_signature");
    expect(await count(await attemptsKey(), DAY)).toBe(1);
    expect(await count(await verifiedKey(), DAY)).toBe(0);
  });

  it("an admitted create counts against the verified budget, not the attempt budget", async () => {
    expect((await send(await verified())).status).toBe(201);
    expect(await count(await verifiedKey(), DAY)).toBe(1);
    expect(await count(await attemptsKey(), DAY)).toBe(0);
  });

  it("an address that spent its 600 refused attempts still creates with a valid signature; its next refusal is 429", async () => {
    await seed(await attemptsKey(), DAY, 599);
    expect((await send(await badSignature())).reason).toBe("bad_signature");
    expect((await send(await verified())).status).toBe(201);
    const over = await send(await badSignature());
    expect(over).toMatchObject({ status: 429, reason: "address_rate" });
    expect(Number(over.retryAfter)).toBe(DAY - ((NOW / 1000) % DAY));
    expect((await send(await verified())).status).toBe(201);
  });

  it("refuses the verified create past the address's daily limit with 429 before writing a record", async () => {
    await seed(await verifiedKey(), DAY, LIMITS.addressVerifiedCreate.limit - 1);
    expect((await send(await verified())).status).toBe(201);
    expect(await rows()).toBe(1);
    const over = await send(await verified());
    expect(over).toMatchObject({ status: 429, reason: "address_verified_rate" });
    expect(Number(over.retryAfter)).toBe(DAY - ((NOW / 1000) % DAY));
    expect(await rows()).toBe(1);
  });

  it("both daily budgets start again at 00:00 UTC", async () => {
    await seed(await attemptsKey(), DAY, 600);
    await seed(await verifiedKey(), DAY, LIMITS.addressVerifiedCreate.limit);
    expect((await send(await verified())).status).toBe(429);
    expect((await send(await badSignature())).status).toBe(429);
    nowMs = (Math.floor(NOW / 1000 / DAY) + 1) * DAY * 1000;
    expect((await send(await verified())).status).toBe(201);
    expect((await send(await badSignature())).reason).toBe("bad_signature");
  });

  it("a refusal past the attempt budget is 429 and writes neither the daily nor the refusal counter", async () => {
    const refusedKey = rateKeys.addressRefused(await hashFor());
    expect((await send(await noCredentials())).reason).toBe("no_credentials");
    expect(await count(refusedKey, 60)).toBe(1);
    await adapter.reset();
    await seed(await attemptsKey(), DAY, 600);
    expect(await send(await noCredentials())).toMatchObject({ status: 429, reason: "address_rate" });
    expect(await send(await badSignature())).toMatchObject({ status: 429, reason: "address_rate" });
    expect(await count(await attemptsKey(), DAY)).toBe(600);
    expect(await count(refusedKey, 60)).toBe(0);
  });

  it("signed creates from every address share the daily ceiling; a refusal at it is 503 and writes no record", async () => {
    expect((await send(await verified("203.0.113.1"))).status).toBe(201);
    expect((await send(await verified("203.0.113.2"))).status).toBe(201);
    expect(await count(ceilingKey, DAY)).toBe(2);
    await seed(ceilingKey, DAY, LIMITS.publicCreate.limit);
    const at = await send(await verified("203.0.113.3"));
    expect(at).toMatchObject({ status: 503, reason: "public_create_ceiling" });
    expect(Number(at.retryAfter)).toBe(DAY - ((NOW / 1000) % DAY));
    expect(await rows()).toBe(2);
    expect(await count(await attemptsKey("203.0.113.3"), DAY)).toBe(0);
  });

  it("an approved API key still creates when the ceiling is spent, and its creates do not count toward it", async () => {
    await addKey();
    await seed(ceilingKey, DAY, LIMITS.publicCreate.limit);
    expect((await send(await verified())).status).toBe(503);
    expect((await send(await serviceCreate())).status).toBe(201);
    expect(await count(ceilingKey, DAY)).toBe(LIMITS.publicCreate.limit);
  });

  it("the ceiling starts again at 00:00 UTC", async () => {
    await seed(ceilingKey, DAY, LIMITS.publicCreate.limit);
    expect((await send(await verified())).status).toBe(503);
    nowMs = (Math.floor(NOW / 1000 / DAY) + 1) * DAY * 1000;
    expect((await send(await verified())).status).toBe(201);
  });

  it("the minute window still counts every attempt: the 31st in a minute is 429", async () => {
    for (let i = 0; i < 15; i++) {
      expect((await send(await verified())).status).toBe(201);
      expect((await send(await badSignature())).reason).toBe("bad_signature");
    }
    expect((await send(await verified())).reason).toBe("address_rate");
  });

  it("the issuer's own daily limit still applies under the larger address budget", async () => {
    const issuer = makeIssuer();
    await seed(rateKeys.issuerCreate(issuer.did, DAY), DAY, LIMITS.issuerCreate[1].limit);
    expect((await send(await signedCreate({ issuer, nowMs }))).reason).toBe("issuer_rate");
  });

  it("requests with a missing or unparseable address share one bucket", async () => {
    expect(await hashFor(null)).toBe(await hashFor("not an address"));
    await seed(await verifiedKey(null), DAY, LIMITS.addressVerifiedCreate.limit);
    expect((await send(await verified("not an address"))).reason).toBe("address_verified_rate");
    expect((await send(await verified())).status).toBe(201);
  });

  it("an approved API key's create counts as verified; a wrong secret counts as a refused attempt", async () => {
    await addKey();
    expect((await send(await serviceCreate())).status).toBe(201);
    expect((await send(await serviceCreate("e".repeat(43)))).reason).toBe("bad_api_key");
    expect(await count(await verifiedKey(), DAY)).toBe(1);
    expect(await count(await attemptsKey(), DAY)).toBe(1);
  });
});
