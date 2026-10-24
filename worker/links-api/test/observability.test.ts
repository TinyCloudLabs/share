import { readFileSync } from "node:fs";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import worker from "../src/worker.ts";
import { createD1Adapter, type Adapter } from "./support/adapters.ts";
import { AUDIENCE, get, makeIssuer, signedCreate, signedDelete, take } from "./support/client.ts";

const SENTINEL_ID = "sentinelid2222222222222222"; // 26 characters of the id alphabet, placed in paths
const SENTINEL_QUERY = "sentinelquery-9f3a";
const SENTINEL_PATH = "sentinel-unknown-path-7c1d";

const WRANGLER = readFileSync(new URL("../wrangler.toml", import.meta.url), "utf8");

describe("wrangler.toml observability", () => {
  it("turns Workers Logs on with invocation logs off", () => {
    expect(WRANGLER).toMatch(/^\[observability\]\s*\nenabled = true/m);
    expect(WRANGLER).toMatch(/^\[observability\.logs\]\s*\ninvocation_logs = false/m);
  });
});

describe("the Worker's console output carries no request path, URL or link id", () => {
  let adapter: Adapter;
  const printed: string[] = [];

  beforeAll(async () => {
    adapter = await createD1Adapter();
  });
  afterAll(async () => {
    await adapter.close();
  });
  afterEach(() => {
    vi.restoreAllMocks();
  });

  function capture(): void {
    for (const method of ["log", "info", "warn", "error", "debug"] as const) {
      vi.spyOn(console, method).mockImplementation((...args: unknown[]) => {
        printed.push(args.map((a) => (typeof a === "string" ? a : JSON.stringify(a))).join(" "));
      });
    }
  }

  it("requests of every kind, a failing database and the scheduled run print only structured counts", async () => {
    await adapter.reset();
    capture();
    const waits: Promise<unknown>[] = [];
    const ctx = { waitUntil: (p: Promise<unknown>) => void waits.push(p) };
    const d1 = adapter.d1;
    if (d1 === null) {
      throw new Error("the D1 adapter has a binding");
    }
    const env = { DB: d1, ADDRESS_SALT: "observability-salt-0123456789" };
    const call = async (request: Request): Promise<string> => {
      const response = await worker.fetch(request, env, ctx);
      return response.text();
    };

    const issuer = makeIssuer();
    const { id } = JSON.parse(await call(await signedCreate({ issuer, nowMs: Date.now() }))) as { id: string };
    await call(get(id));
    await call(get(SENTINEL_ID));
    await call(take(SENTINEL_ID));
    await call(await signedDelete({ issuer, id: SENTINEL_ID, nowMs: Date.now() }));
    await call(new Request(`${AUDIENCE}/v1/links/${SENTINEL_ID}?q=${SENTINEL_QUERY}`));
    await call(new Request(`${AUDIENCE}/${SENTINEL_PATH}/${SENTINEL_ID}?q=${SENTINEL_QUERY}`));
    await call(new Request(`${AUDIENCE}/v1/links`, { method: "OPTIONS", headers: { Origin: "https://share.tinycloud.xyz" } }));
    // A database that fails every call: the handler answers 500 and prints nothing.
    const broken = { DB: { prepare: () => { throw new Error(`boom ${SENTINEL_ID}`); }, batch: () => { throw new Error("boom"); } }, ADDRESS_SALT: env.ADDRESS_SALT };
    const failed = await worker.fetch(get(SENTINEL_ID), broken as unknown as typeof env, ctx);
    expect(failed.status).toBe(500);
    // A missing salt: the handler answers 500 and prints nothing.
    const unsalted = await worker.fetch(get(SENTINEL_ID), { DB: d1 } as unknown as typeof env, ctx);
    expect(unsalted.status).toBe(500);
    await Promise.allSettled(waits);

    await worker.scheduled({}, env, ctx);
    await Promise.allSettled(waits);

    const output = printed.join("\n");
    for (const needle of [SENTINEL_ID, SENTINEL_QUERY, SENTINEL_PATH, id, issuer.did, "/v1/links", AUDIENCE, "boom"]) {
      expect(output.includes(needle), `console output contains ${needle}`).toBe(false);
    }
    expect(printed.length).toBeGreaterThan(0);
    for (const line of printed) {
      const parsed = JSON.parse(line) as { event?: string; alert?: string };
      expect(parsed.event === "links.health" || typeof parsed.alert === "string").toBe(true);
    }
  });
});
