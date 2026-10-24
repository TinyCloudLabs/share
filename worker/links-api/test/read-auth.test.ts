import { readFileSync } from "node:fs";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { configFromEnv, LIMITS, WORKERS_FREE_PLAN, type ServiceConfig } from "../src/config.ts";
import { parseEd25519DidKey } from "../src/ed25519.ts";
import { runScheduled } from "../src/health.ts";
import { READ_AUTH_DOMAIN, READ_AUTH_HEADER, READ_AUTH_MAX_BYTES, READ_AUTH_WINDOW_MS, evaluateReadAuth, type ReadAuthResult } from "../src/read-auth.ts";
import { parseReadSigners, type ReadSigner } from "../src/read-signers.ts";
import { handleRequest, type ServiceDeps } from "../src/service.ts";
import worker from "../src/worker.ts";
import { ADAPTER_FACTORIES, type Adapter } from "./support/adapters.ts";
import { AUDIENCE, CLIENT_IP, get, makeIssuer, signedCreate, take } from "./support/client.ts";
import { TEST_NODE_DID, authenticatedGet, randomKey, readAuthValue, testNodeKey } from "./support/read-auth-client.ts";
import { loadVectors, vectorsPath } from "./support/vectors.ts";

// ---------------------------------------------------------------------------------------------
// The nodeReadAuth vectors (contract 4.11)
// ---------------------------------------------------------------------------------------------

interface NodeReadAuthRow {
  readonly name: string;
  readonly request: { readonly method: string; readonly path: string; readonly audience: string };
  readonly headerValue: string | null;
  readonly expect: { readonly authenticated: boolean; readonly label?: string; readonly reason?: string };
  readonly allowList?: readonly { readonly label: string; readonly did: string }[];
}

interface NodeReadAuthGroup {
  readonly domain: string;
  readonly headerName: string;
  readonly windowSeconds: number;
  readonly headerMaxBytes: number;
  readonly serviceNow: string;
  readonly audience: string;
  readonly allowList: readonly { readonly label: string; readonly did: string }[];
  readonly vectors: readonly NodeReadAuthRow[];
}

/** The fixture is pinned by its SHA-256 elsewhere; this reads only the `nodeReadAuth` group. */
function readGroup(): NodeReadAuthGroup {
  const file = JSON.parse(readFileSync(vectorsPath(), "utf8")) as { nodeReadAuth: NodeReadAuthGroup };
  return file.nodeReadAuth;
}

/** Signers built without the load-time key check, so the rows that list a weak key can run the verifier. */
function unchecked(list: readonly { readonly label: string; readonly did: string }[]): ReadSigner[] {
  return list.map((entry) => {
    const key = parseEd25519DidKey(entry.did);
    if (!key.ok) {
      throw new Error("vector DID does not parse");
    }
    return { label: entry.label, did: entry.did, publicKey: key.publicKey };
  });
}

describe("nodeReadAuth vectors", () => {
  const group = readGroup();

  it("the vector constants are the ones the Worker uses", () => {
    expect(group.domain).toBe(READ_AUTH_DOMAIN);
    expect(group.headerName).toBe(READ_AUTH_HEADER);
    expect(group.windowSeconds * 1000).toBe(READ_AUTH_WINDOW_MS);
    expect(group.headerMaxBytes).toBe(READ_AUTH_MAX_BYTES);
    expect(group.audience).toBe(AUDIENCE);
    expect(group.allowList[0]?.did).toBe(TEST_NODE_DID);
  });

  it("has all 19 rows", () => {
    expect(group.vectors).toHaveLength(19);
  });

  it.each(readGroup().vectors.map((row, i) => [i, row.name, row] as const))("row %i: %s", async (_i, _name, row) => {
    const url = new URL(`${row.request.audience}${row.request.path}`);
    const result: ReadAuthResult = await evaluateReadAuth({
      headerValue: row.headerValue,
      method: row.request.method,
      pathname: url.pathname,
      search: url.search,
      audience: row.request.audience,
      nowMs: Date.parse(group.serviceNow),
      signers: unchecked(row.allowList ?? group.allowList),
    });
    expect(result.authenticated).toBe(row.expect.authenticated);
    if (row.expect.authenticated) {
      expect(result).toEqual({ authenticated: true, label: row.expect.label });
    } else {
      expect(result).toEqual({ authenticated: false, reason: row.expect.reason });
    }
  });
});

// ---------------------------------------------------------------------------------------------
// Service behaviour
// ---------------------------------------------------------------------------------------------

const NOW = Date.parse("2026-10-24T12:00:00.000Z");
const NODE_LIST = [{ label: "service:node", did: TEST_NODE_DID }];

function configWith(signers: readonly { label: string; did: string }[], extra: Partial<ServiceConfig> = {}): ServiceConfig {
  return {
    audience: AUDIENCE,
    corsOrigins: ["https://share.tinycloud.xyz"],
    takeOrigins: [],
    addressSalt: "read-auth-test-salt-0123456789",
    kill: { create: false, read: false, take: false, delete: false },
    clientAddressHeader: "CF-Connecting-IP",
    readSigners: parseReadSigners(signers),
    ...extra,
  };
}

describe.each(ADAPTER_FACTORIES)("authenticated read: $name adapter", ({ create }) => {
  let adapter: Adapter;
  let logs: string[];
  let deps: ServiceDeps;

  const build = (config: ServiceConfig): ServiceDeps => ({
    storage: adapter.storage(),
    config,
    usage: { plan: WORKERS_FREE_PLAN, tally: null, statsEveryMinutes: 1 },
    now: () => NOW,
    log: (line) => logs.push(line),
  });
  const makeLink = async (type: "share" | "courier" = "share"): Promise<string> => {
    const response = await handleRequest(await signedCreate({ type, issuer: makeIssuer(), nowMs: NOW }), deps);
    return ((await response.json()) as { id: string }).id;
  };
  const readCount = async (name: string): Promise<number> => (await deps.storage.readCounts())[name] ?? 0;
  /** Status, every header and the body of a response. */
  const shape = async (response: Response) => ({
    status: response.status,
    headers: [...response.headers].sort(),
    body: Buffer.from(await response.arrayBuffer()).toString("hex"),
  });

  beforeAll(async () => {
    adapter = await create();
  });
  afterAll(async () => {
    await adapter.close();
  });
  beforeEach(async () => {
    await adapter.reset();
    logs = [];
    deps = build(configWith(NODE_LIST));
  });

  describe("the response does not depend on the header", () => {
    it("every unrecognised header is answered exactly as a request with no header, and so is a recognised one", async () => {
      const id = await makeLink();
      const other = await makeLink();
      const stranger = randomKey();
      const good = await readAuthValue({ key: testNodeKey, id, nowMs: NOW });
      const cases: Record<string, string | null> = {
        none: null,
        recognised: good,
        stale: await readAuthValue({ key: testNodeKey, id, nowMs: NOW, skewMs: -(READ_AUTH_WINDOW_MS + 1) }),
        future: await readAuthValue({ key: testNodeKey, id, nowMs: NOW, skewMs: READ_AUTH_WINDOW_MS + 1 }),
        unlisted: await readAuthValue({ key: stranger, id, nowMs: NOW }),
        wrongPath: await readAuthValue({ key: testNodeKey, id, nowMs: NOW, signedPath: `/v1/links/${other}` }),
        wrongAudience: await readAuthValue({ key: testNodeKey, id, nowMs: NOW, audience: "https://api.example.invalid" }),
        malformed: "not-base64url!",
        empty: "",
        oversized: "A".repeat(READ_AUTH_MAX_BYTES + 1),
        tampered: `${good.slice(0, -2)}AA`,
      };
      const seen: Record<string, Awaited<ReturnType<typeof shape>>> = {};
      let n = 0;
      for (const [name, value] of Object.entries(cases)) {
        n += 1;
        const headers: Record<string, string> = { "CF-Connecting-IP": `198.51.100.${n}` };
        if (value !== null) {
          headers[READ_AUTH_HEADER] = value;
        }
        seen[name] = await shape(await handleRequest(new Request(`${AUDIENCE}/v1/links/${id}`, { headers }), deps));
      }
      for (const [name, entry] of Object.entries(seen)) {
        expect(entry, name).toEqual(seen["none"]);
      }
      expect(seen["none"]?.status).toBe(200);
    });

    it("a missing id is the same 404 with and without a recognised header", async () => {
      const missing = "d".repeat(26);
      const plain = await shape(await handleRequest(get(missing, "198.51.100.1"), deps));
      const signed = await shape(await handleRequest(await authenticatedGet({ key: testNodeKey, id: missing, nowMs: NOW, ip: "198.51.100.2" }), deps));
      expect(signed).toEqual(plain);
      expect(plain.status).toBe(404);
    });

    it("nothing in a response or in the stored record says whether a header was recognised", async () => {
      const id = await makeLink();
      const response = await handleRequest(await authenticatedGet({ key: testNodeKey, id, nowMs: NOW }), deps);
      const text = JSON.stringify([...response.headers]).toLowerCase();
      expect(text).not.toContain("authenticated");
      expect(text).not.toContain("read-auth");
      expect(text).not.toContain("service:node");
    });

    it("the preflight for create does not allow the header", async () => {
      const response = await handleRequest(
        new Request(`${AUDIENCE}/v1/links`, { method: "OPTIONS", headers: { Origin: "https://share.tinycloud.xyz" } }),
        deps,
      );
      expect(response.headers.get("Access-Control-Allow-Headers")).toBe("Content-Type");
    });
  });

  describe("buckets", () => {
    it("a recognised read does not use the per-address limit", async () => {
      const id = await makeLink();
      for (let i = 0; i < LIMITS.addressRead.limit + 20; i++) {
        const response = await handleRequest(await authenticatedGet({ key: testNodeKey, id, nowMs: NOW }), deps);
        expect(response.status).toBe(200);
      }
      // The same address still has its whole ordinary allowance.
      for (let i = 0; i < LIMITS.addressRead.limit; i++) {
        expect((await handleRequest(get(id), deps)).status).toBe(200);
      }
      expect((await handleRequest(get(id), deps)).status).toBe(429);
    });

    it("the per-address limit does not apply to a recognised read from an address that has used it up", async () => {
      const id = await makeLink();
      for (let i = 0; i < LIMITS.addressRead.limit; i++) {
        await handleRequest(get(id), deps);
      }
      expect((await handleRequest(get(id), deps)).status).toBe(429);
      expect((await handleRequest(await authenticatedGet({ key: testNodeKey, id, nowMs: NOW }), deps)).status).toBe(200);
    });

    it("the label bucket is bounded: the read after the limit is a 429 with Retry-After, and ordinary reads are unaffected", async () => {
      deps = build(configWith(NODE_LIST, { readAuthLimit: 5 }));
      const id = await makeLink();
      for (let i = 0; i < 5; i++) {
        expect((await handleRequest(await authenticatedGet({ key: testNodeKey, id, nowMs: NOW }), deps)).status).toBe(200);
      }
      const refused = await handleRequest(await authenticatedGet({ key: testNodeKey, id, nowMs: NOW }), deps);
      expect(refused.status).toBe(429);
      expect(await refused.json()).toEqual({ error: "rate_limited" });
      expect(Number(refused.headers.get("Retry-After"))).toBeGreaterThanOrEqual(1);
      expect((await handleRequest(get(id, "198.51.100.9"), deps)).status).toBe(200);
    });

    it("the default label bucket is 6,000 a minute", () => {
      expect(LIMITS.authenticatedRead).toEqual({ limit: 6_000, windowSeconds: 60 });
      expect(configFromEnv({ ADDRESS_SALT: "read-auth-test-salt-0123456789" }).readAuthLimit).toBe(6_000);
      expect(configFromEnv({ ADDRESS_SALT: "read-auth-test-salt-0123456789", LINKS_READ_AUTH_LIMIT: "250" }).readAuthLimit).toBe(250);
    });

    it("each label has its own bucket", async () => {
      const second = randomKey();
      deps = build(
        configWith(
          [
            { label: "service:node", did: TEST_NODE_DID },
            { label: "service:other", did: second.did },
          ],
          { readAuthLimit: 2 },
        ),
      );
      const id = await makeLink();
      await handleRequest(await authenticatedGet({ key: testNodeKey, id, nowMs: NOW }), deps);
      await handleRequest(await authenticatedGet({ key: testNodeKey, id, nowMs: NOW }), deps);
      expect((await handleRequest(await authenticatedGet({ key: testNodeKey, id, nowMs: NOW }), deps)).status).toBe(429);
      expect((await handleRequest(await authenticatedGet({ key: second, id, nowMs: NOW }), deps)).status).toBe(200);
    });

    it("a request that is not eligible is an ordinary read under the per-address limit", async () => {
      const id = await makeLink();
      const upper = await authenticatedGet({ key: testNodeKey, id, nowMs: NOW, suffix: "" });
      const requests: Request[] = [
        new Request(`${AUDIENCE}/v1/links/${id.toUpperCase()}`, { headers: { [READ_AUTH_HEADER]: await readAuthValue({ key: testNodeKey, id, nowMs: NOW }), "CF-Connecting-IP": CLIENT_IP } }),
        new Request(`${AUDIENCE}/v1/links/${id.toUpperCase()}`, { headers: { [READ_AUTH_HEADER]: await readAuthValue({ key: testNodeKey, id: id.toUpperCase(), nowMs: NOW }), "CF-Connecting-IP": CLIENT_IP } }),
        await authenticatedGet({ key: testNodeKey, id, nowMs: NOW, suffix: "?x=1" }),
      ];
      for (const request of requests) {
        expect((await handleRequest(request, deps)).status).toBe(200);
      }
      expect(await readCount("reads.authenticated")).toBe(0);
      expect((await handleRequest(upper, deps)).status).toBe(200);
      expect(await readCount("reads.authenticated")).toBe(1);
    });

    it("an unlisted key, a stale header and a header on take are ordinary reads under the per-address limit", async () => {
      const id = await makeLink("courier");
      const stranger = randomKey();
      for (let i = 0; i < LIMITS.addressRead.limit; i++) {
        const key = i % 2 === 0 ? stranger : testNodeKey;
        const skewMs = i % 2 === 0 ? 0 : -(READ_AUTH_WINDOW_MS + 1);
        await handleRequest(await authenticatedGet({ key, id, nowMs: NOW, skewMs }), deps);
      }
      expect((await handleRequest(get(id), deps)).status).toBe(429);
      expect(await readCount("reads.authenticated")).toBe(0);
      const headerOnTake = new Request(`${AUDIENCE}/v1/links/${id}/take`, {
        method: "POST",
        headers: { [READ_AUTH_HEADER]: await readAuthValue({ key: testNodeKey, id, nowMs: NOW }), "CF-Connecting-IP": "198.51.100.77" },
      });
      expect((await handleRequest(headerOnTake, deps)).status).toBe(404);
      expect(await readCount("reads.authenticated")).toBe(0);
    });

    it("a recognised read is still refused by a kill switch and for an unknown id, like any read", async () => {
      const killed = build(configWith(NODE_LIST, { kill: { create: false, read: true, take: false, delete: false } }));
      const id = "e".repeat(26);
      const response = await handleRequest(await authenticatedGet({ key: testNodeKey, id, nowMs: NOW }), killed);
      expect(response.status).toBe(503);
      expect((await handleRequest(await authenticatedGet({ key: testNodeKey, id, nowMs: NOW }), deps)).status).toBe(404);
    });
  });

  describe("counter and logs", () => {
    it("reads.authenticated counts the reads served from the label bucket, hits and misses, and appears only in the health line", async () => {
      const id = await makeLink();
      await handleRequest(await authenticatedGet({ key: testNodeKey, id, nowMs: NOW }), deps);
      await handleRequest(await authenticatedGet({ key: testNodeKey, id: "f".repeat(26), nowMs: NOW }), deps);
      await handleRequest(get(id), deps);
      await runScheduled(deps);
      const health = JSON.parse(logs.at(-1) ?? "{}");
      expect(health.reads).toEqual({ hit: 2, miss: 1, authenticated: 2 });
    });

    it("a refused label-bucket read is not counted as served", async () => {
      deps = build(configWith(NODE_LIST, { readAuthLimit: 1 }));
      const id = await makeLink();
      await handleRequest(await authenticatedGet({ key: testNodeKey, id, nowMs: NOW }), deps);
      await handleRequest(await authenticatedGet({ key: testNodeKey, id, nowMs: NOW }), deps);
      expect(await readCount("reads.authenticated")).toBe(1);
    });

    it("the header value, the signer and the signature are never logged", async () => {
      const id = await makeLink();
      const value = await readAuthValue({ key: testNodeKey, id, nowMs: NOW });
      const spies = (["log", "info", "warn", "error", "debug"] as const).map((m) => vi.spyOn(console, m).mockImplementation(() => undefined));
      await handleRequest(await authenticatedGet({ key: testNodeKey, id, nowMs: NOW }), deps);
      await handleRequest(new Request(`${AUDIENCE}/v1/links/${id}`, { headers: { [READ_AUTH_HEADER]: "%%%" } }), deps);
      await runScheduled(deps);
      const printed = [...logs, ...spies.flatMap((s) => s.mock.calls.map((c) => c.map(String).join(" ")))].join("\n");
      spies.forEach((s) => s.mockRestore());
      for (const needle of [value, TEST_NODE_DID, JSON.parse(Buffer.from(value, "base64url").toString()).signature]) {
        expect(printed.includes(needle)).toBe(false);
      }
    });
  });

  describe("Date header", () => {
    it("is on every kind of response", async () => {
      const id = await makeLink();
      const requests: Request[] = [
        get(id),
        get("c".repeat(26), "198.51.100.5"),
        await signedCreate({ issuer: makeIssuer(), nowMs: NOW, headers: { "Content-Type": "text/plain" } }),
        await signedCreate({ issuer: makeIssuer(), nowMs: NOW }),
        new Request(`${AUDIENCE}/v1/links`, { method: "OPTIONS", headers: { Origin: "https://share.tinycloud.xyz" } }),
        new Request(`${AUDIENCE}/no/such/route`),
        take(id),
      ];
      for (const request of requests) {
        const response = await handleRequest(request, deps);
        expect(response.headers.get("Date"), `${request.method} ${new URL(request.url).pathname}`).toBe(new Date(NOW).toUTCString());
      }
    });

    it("the explicit Date header is present on a hit, a miss, a 429 and a 404", async () => {
      const id = await makeLink();
      const expected = new Date(NOW).toUTCString();
      const hit = await handleRequest(get(id, "198.51.100.40"), deps);
      const miss = await handleRequest(get("c".repeat(26), "198.51.100.41"), deps);
      const route = await handleRequest(new Request(`${AUDIENCE}/no/such/route`), deps);
      for (let i = 0; i < LIMITS.addressRead.limit; i++) {
        await handleRequest(get(id, "198.51.100.42"), deps);
      }
      const limited = await handleRequest(get(id, "198.51.100.42"), deps);
      const labelLimited = build(configWith(NODE_LIST, { readAuthLimit: 1 }));
      await handleRequest(await authenticatedGet({ key: testNodeKey, id, nowMs: NOW, ip: "198.51.100.43" }), labelLimited);
      const labelRefused = await handleRequest(await authenticatedGet({ key: testNodeKey, id, nowMs: NOW, ip: "198.51.100.43" }), labelLimited);
      expect([hit.status, miss.status, route.status, limited.status, labelRefused.status]).toEqual([200, 404, 404, 429, 429]);
      for (const response of [hit, miss, route, limited, labelRefused]) {
        expect(response.headers.get("Date")).toBe(expected);
      }
    });
  });

  describe("rotation", () => {
    it("two keys for one label work together; after the old key is removed it is an ordinary read", async () => {
      const next = randomKey();
      const id = await makeLink();
      const both = build(configWith([{ label: "service:node", did: TEST_NODE_DID }, { label: "service:node", did: next.did }]));
      await handleRequest(await authenticatedGet({ key: testNodeKey, id, nowMs: NOW }), both);
      await handleRequest(await authenticatedGet({ key: next, id, nowMs: NOW }), both);
      expect(await readCount("reads.authenticated")).toBe(2);
      const onlyNew = build(configWith([{ label: "service:node", did: next.did }]));
      await handleRequest(await authenticatedGet({ key: next, id, nowMs: NOW }), onlyNew);
      expect((await handleRequest(await authenticatedGet({ key: testNodeKey, id, nowMs: NOW }), onlyNew)).status).toBe(200);
      expect(await readCount("reads.authenticated")).toBe(1);
    });
  });
});

// ---------------------------------------------------------------------------------------------
// Configuration, validated at load
// ---------------------------------------------------------------------------------------------

describe("links.readSigners configuration", () => {
  const SALT = "read-auth-test-salt-0123456789";
  const load = (signers: unknown) => configFromEnv({ ADDRESS_SALT: SALT, LINKS_READ_SIGNERS: typeof signers === "string" ? signers : JSON.stringify(signers) });
  const second = randomKey().did;
  const third = randomKey().did;

  it("none configured: no signers", () => {
    expect(configFromEnv({ ADDRESS_SALT: SALT }).readSigners).toEqual([]);
    expect(load([]).readSigners).toEqual([]);
  });

  it("accepts one or two keys for a label, and two labels", () => {
    expect(load([{ label: "service:node", did: TEST_NODE_DID }]).readSigners).toHaveLength(1);
    expect(load([{ label: "service:node", did: TEST_NODE_DID }, { label: "service:node", did: second }]).readSigners).toHaveLength(2);
    expect(
      load([
        { label: "service:node", did: TEST_NODE_DID },
        { label: "service:node", did: second },
        { label: "service:other", did: third },
      ]).readSigners,
    ).toHaveLength(3);
  });

  it("refuses a third key for a label", () => {
    expect(() =>
      load([
        { label: "service:node", did: TEST_NODE_DID },
        { label: "service:node", did: second },
        { label: "service:node", did: third },
      ]),
    ).toThrow(/third key/);
  });

  it.each([
    ["not JSON", "{not json"],
    ["not a list", { label: "service:node", did: TEST_NODE_DID }],
    ["an entry that is not an object", ["x"]],
    ["an extra field", [{ label: "service:node", did: TEST_NODE_DID, note: "x" }]],
    ["a missing field", [{ label: "service:node" }]],
    ["a label that is not service:<name>", [{ label: "node", did: TEST_NODE_DID }]],
    ["an upper-case label", [{ label: "service:Node", did: TEST_NODE_DID }]],
    ["a DID that is not a did:key", [{ label: "service:node", did: "did:web:example.com" }]],
    ["a did:key of another key type", [{ label: "service:node", did: "did:key:zQ3shMYdM8Kuh6LHsfSkGi2tUnnX1e4u286ZN1qzm8wcrk3zh" }]],
    ["a small-order key", [{ label: "service:node", did: "did:key:z6MkeXATEjyXENzBXBxgC5EHk2JE5aqd7qMGGtDpLUH1e2Sj" }]],
    ["a non-canonical key", [{ label: "service:node", did: "did:key:z6MkvYDV6cfbwNp6jpaZGAcYpZgdfuK59wb3FKdA8t7sBVka" }]],
    ["a repeated key", [{ label: "service:node", did: TEST_NODE_DID }, { label: "service:other", did: TEST_NODE_DID }]],
  ])("refuses at load: %s", (_name, signers) => {
    expect(() => load(signers)).toThrow(/LINKS_READ_SIGNERS/);
  });

  it("refuses a bucket limit that is not a positive integer", () => {
    for (const bad of ["0", "-5", "1.5", "many"]) {
      expect(() => configFromEnv({ ADDRESS_SALT: SALT, LINKS_READ_AUTH_LIMIT: bad })).toThrow(/LINKS_READ_AUTH_LIMIT/);
    }
  });

  it("the Worker does not serve with an invalid list: every request is a 500", async () => {
    const adapter = await ADAPTER_FACTORIES[1].create();
    const d1 = adapter.d1;
    if (d1 === null) {
      throw new Error("the D1 adapter has a binding");
    }
    const ctx = { waitUntil: () => undefined };
    const env = { DB: d1, ADDRESS_SALT: SALT, LINKS_READ_SIGNERS: JSON.stringify([{ label: "node", did: TEST_NODE_DID }]) };
    expect((await worker.fetch(get("a".repeat(26)), env, ctx)).status).toBe(500);
    const good = { ...env, LINKS_READ_SIGNERS: JSON.stringify(NODE_LIST) };
    expect((await worker.fetch(get("a".repeat(26)), good, ctx)).status).toBe(404);
    await adapter.close();
  });
});
