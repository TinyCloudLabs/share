import { randomBytes } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { base64UrlEncode } from "../src/bytes.ts";
import { WORKERS_FREE_PLAN, type ServiceConfig } from "../src/config.ts";
import { runScheduled } from "../src/health.ts";
import { handleRequest, type ServiceDeps } from "../src/service.ts";
import { ADAPTER_FACTORIES, type Adapter } from "./support/adapters.ts";
import { AUDIENCE, CLIENT_IP, get, makeIssuer, sealBody, signedCreate, signedDelete, take } from "./support/client.ts";

const NOW = Date.UTC(2026, 9, 24, 12, 0, 0);
const CONFIG: ServiceConfig = {
  audience: AUDIENCE,
  corsOrigins: ["https://share.tinycloud.xyz"],
  takeOrigins: [],
  addressSalt: "sentinel-salt-0123456789",
  kill: { create: false, read: false, take: false, delete: false },
  clientAddressHeader: "CF-Connecting-IP",
};
const TABLES = ["links", "rl", "nonces", "blocked", "api_keys", "metrics", "usage_daily"];

/** Every way the content key can be written: raw, base64url, hex, and the link fragment that carries it. */
function keyForms(key: Uint8Array): string[] {
  const b64 = base64UrlEncode(key);
  return [b64, Buffer.from(key).toString("hex"), Buffer.from(key).toString("base64"), `k=${b64}`, `#v=4&k=${b64}`];
}

describe.each(ADAPTER_FACTORIES)("the content key never reaches the service: $name adapter", ({ create }) => {
  let adapter: Adapter;
  beforeAll(async () => {
    adapter = await create();
  });
  afterAll(async () => {
    await adapter.close();
  });

  it("a sentinel key sealed into the body is absent from the database, every request and response, and every log line", async () => {
    await adapter.reset();
    const key = randomBytes(32);
    const logs: string[] = [];
    const wire: string[] = [];
    const deps: ServiceDeps = {
      storage: adapter.storage(),
      config: CONFIG,
      usage: { plan: WORKERS_FREE_PLAN, tally: null, statsEveryMinutes: 1 },
      now: () => NOW,
      log: (line) => logs.push(line),
    };
    const send = async (request: Request): Promise<Response> => {
      wire.push(await request.clone().text(), JSON.stringify([...request.headers]), request.url);
      const response = await handleRequest(request, deps);
      wire.push(await response.clone().text(), JSON.stringify([...response.headers]));
      return response;
    };

    const issuer = makeIssuer();
    const sealed = sealBody(`{"issuer":"${issuer.did}","k":"sentinel"}`, key);
    const created = await send(await signedCreate({ issuer, body: sealed, nowMs: NOW }));
    const { id } = (await created.json()) as { id: string };
    await send(get(id));
    await send(get("z".repeat(26), "203.0.113.5"));
    await send(await signedCreate({ issuer: makeIssuer(), nowMs: NOW, headers: { Origin: "https://evil.example" } }));
    const login = makeIssuer();
    const loginCreated = await send(await signedCreate({ type: "openkey-login", issuer: login, body: sealBody("login", key), nowMs: NOW }));
    await send(take(((await loginCreated.json()) as { id: string }).id));
    await send(await signedDelete({ issuer, id, nowMs: NOW }));
    await runScheduled(deps);

    const dump = JSON.stringify(
      await Promise.all(
        TABLES.map(async (table) => [table, await adapter.driver.all<Record<string, unknown>>(`SELECT * FROM ${table}`, [])]),
      ),
      (_k, value) => (value instanceof Uint8Array || value instanceof ArrayBuffer ? Buffer.from(value as Uint8Array).toString("hex") : value),
    );
    const haystacks = { database: dump, wire: wire.join("\n"), logs: logs.join("\n") };
    for (const [where, text] of Object.entries(haystacks)) {
      for (const form of keyForms(key)) {
        expect(text.includes(form), `${where} contains the key as ${form.slice(0, 6)}...`).toBe(false);
      }
    }
    expect(wire.length).toBeGreaterThan(10);
  });

  it("log lines carry no id, issuer, nonce, body digest, address or bearer token", async () => {
    await adapter.reset();
    const logs: string[] = [];
    const secret = "q".repeat(43);
    const deps: ServiceDeps = {
      storage: adapter.storage(),
      config: CONFIG,
      usage: { plan: WORKERS_FREE_PLAN, tally: null, statsEveryMinutes: 1 },
      now: () => NOW,
      log: (line) => logs.push(line),
    };
    const issuer = makeIssuer();
    const request = await signedCreate({ issuer, nowMs: NOW });
    const text = await request.clone().text();
    const header = (JSON.parse(text) as { header: { nonce: string; bodyCid: string } }).header;
    const id = ((await (await handleRequest(request, deps)).json()) as { id: string }).id;
    await handleRequest(get(id), deps);
    await handleRequest(new Request(`${AUDIENCE}/v1/links`, { method: "POST", headers: { Authorization: `Bearer tlk_abcdefgh_${secret}`, "Content-Type": "application/json" }, body: "{}" }), deps);
    await runScheduled(deps);
    expect(logs.length).toBeGreaterThan(0);
    for (const needle of [id, issuer.did, header.nonce, header.bodyCid, CLIENT_IP, secret, "tlk_"]) {
      expect(logs.join("\n").includes(needle), `a log line contains ${needle.slice(0, 8)}`).toBe(false);
    }
  });
});
