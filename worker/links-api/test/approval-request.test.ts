import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { randomBytes } from "node:crypto";
import { base64UrlDecode, cidForBytes } from "../src/bytes.ts";
import type { LinkType, ServiceConfig } from "../src/config.ts";
import { handleRequest, type ServiceDeps } from "../src/service.ts";
import { ADAPTER_FACTORIES, type Adapter } from "./support/adapters.ts";
import { AUDIENCE, get, makeIssuer, sealBody, signedCreate, take } from "./support/client.ts";

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
});
