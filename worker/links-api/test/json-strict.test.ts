import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { WORKERS_FREE_PLAN, type ServiceConfig } from "../src/config.ts";
import { hasDuplicateKey } from "../src/json-strict.ts";
import { handleRequest, handleRequestWithReason, type ServiceDeps } from "../src/service.ts";
import { createSqliteAdapter, type Adapter } from "./support/adapters.ts";
import { AUDIENCE, CLIENT_IP, makeIssuer, signedCreate, signedDelete } from "./support/client.ts";

describe("hasDuplicateKey", () => {
  it.each([
    ["an empty object", "{}"],
    ["distinct keys", '{"a":1,"b":2}'],
    ["the same key in different objects", '{"a":{"a":1},"b":{"a":2}}'],
    ["the same key in sibling array elements", '[{"a":1},{"a":2},{"a":3}]'],
    ["a value equal to a key", '{"a":"a","b":"a"}'],
    ["values that swap with keys", '{"a":"b","b":"a"}'],
    ["repeated strings in an array", '{"k":["a","a","a"]}'],
    ["a top-level array of strings", '["a","a"]'],
    ["a quoted comma and key inside a value", '{"a":"x\\",\\"b\\":1","b":2}'],
    ["an escaped quote in one key only", '{"a\\"b":1,"a":2}'],
    ["an escaped backslash in one key only", '{"a\\\\":1,"a":2}'],
    ["keys that differ in case", '{"a":1,"\\u0041":2}'],
    ["a Latin and a Cyrillic letter", '{"a":1,"\u0430":2}'],
    ["a trailing space in one key", '{"a":1,"a ":2}'],
    ["one key before and after a nested object", '{"a":{"b":1},"c":{"b":2}}'],
    ["literals, numbers and whitespace", ' { "a" : 1 , "b" : [ true , null , -1.5e3 ] , "c" : { } } '],
    ["__proto__ once", '{"__proto__":1}'],
  ])("accepts %s", (_name, text) => {
    expect(hasDuplicateKey(text)).toBe(false);
  });

  it.each([
    ["a top-level duplicate", '{"a":1,"a":2}'],
    ["a duplicate after a nested value", '{"a":{"b":1},"a":2}'],
    ["a duplicate in a nested object", '{"x":{"a":1,"a":2}}'],
    ["a duplicate in an array element", '[{"ok":1},{"a":1,"a":2}]'],
    ["a duplicate deep in the text", `${'{"d":'.repeat(40)}{"a":1,"a":2}${"}".repeat(40)}`],
    ["a duplicate with different values", '{"type":"share","type":"courier"}'],
    ["an escaped quote in both keys", '{"a\\"b":1,"a\\"b":2}'],
    ["an escaped backslash in both keys", '{"a\\\\":1,"a\\\\":2}'],
    ["a unicode escape that spells the other key", '{"a":1,"\\u0061":2}'],
    ["both keys written as escapes", '{"\\u0061":1,"\\u0061":2}'],
    ["an escape and the literal character", '{"\\u00e9":1,"\u00e9":2}'],
    ["a surrogate pair and the literal character", '{"\\ud83d\\ude00":1,"\u{1f600}":2}'],
    ["a short escape and its unicode form", '{"\\n":1,"\\u000a":2}'],
    ["__proto__ twice", '{"__proto__":1,"__proto__":2}'],
    ["the empty key twice", '{"":1,"":2}'],
    ["a duplicate after arrays and strings with commas", '{"a":["x,y","z"],"b":"c,\\"d","a":1}'],
  ])("refuses %s", (_name, text) => {
    expect(hasDuplicateKey(text)).toBe(true);
  });

  it("leaves text that is not JSON to JSON.parse: unterminated strings and invalid escapes are not reported", () => {
    expect(hasDuplicateKey('{"a":1,"a')).toBe(false);
    expect(hasDuplicateKey('{"a\\q":1,"a\\q":2}')).toBe(false);
    expect(() => JSON.parse('{"a\\q":1,"a\\q":2}')).toThrow();
  });

  const work = (text: string): { visits: number; keyChars: number; found: boolean } => {
    const counter = { visits: 0, keyChars: 0 };
    const found = hasDuplicateKey(text, counter);
    return { ...counter, found };
  };
  const keys = (n: number) => `{${Array.from({ length: n }, (_, i) => `"key${i}":${i}`).join(",")}}`;

  it("is linear: every character is looked at at most once, so the work grows with the text and no faster", () => {
    const sizes = [1_000, 8_000, 64_000];
    const counts = sizes.map((n) => {
      const text = keys(n);
      const w = work(text);
      expect(w.found).toBe(false);
      expect(w.visits).toBeLessThanOrEqual(text.length);
      expect(w.keyChars).toBeLessThanOrEqual(text.length);
      return { length: text.length, visits: w.visits };
    });
    // Eight times the keys: the work grows by the same factor as the text (within 1 %), not by its square.
    for (let i = 1; i < counts.length; i++) {
      const previous = counts[i - 1];
      const current = counts[i];
      expect(previous && current && current.visits / previous.visits / (current.length / previous.length)).toBeGreaterThan(0.99);
      expect(previous && current && current.visits / previous.visits / (current.length / previous.length)).toBeLessThan(1.01);
    }
  });

  it("looks at each character once for long strings, many escapes and deep nesting", () => {
    const texts = [
      `{"a":"${"x".repeat(100_000)}","b":"${'\\"'.repeat(50_000)}"}`,
      `{${Array.from({ length: 20_000 }, (_, i) => `"k\\u0041${i}":${i}`).join(",")}}`,
      `{"${"\\\\".repeat(50_000)}":1,"${"\\u0061".repeat(20_000)}":2}`,
      "[".repeat(200_000) + "]".repeat(200_000),
      '{"a":'.repeat(100_000) + "1" + "}".repeat(100_000),
      `[${Array.from({ length: 30_000 }, (_, i) => `{"id":${i},"tags":["a","b"]}`).join(",")}]`,
    ];
    for (const text of texts) {
      const w = work(text);
      expect(w.found).toBe(false);
      expect(w.visits).toBeLessThanOrEqual(text.length);
      expect(w.keyChars).toBeLessThanOrEqual(text.length);
    }
  });

  it("stops at the first repeat: the work is the text up to that point, however much follows", () => {
    const w = work(`{"a":1,"a":2}${" ".repeat(1_000_000)}`);
    expect(w.found).toBe(true);
    expect(w.visits).toBeLessThan(20);
    const late = `${keys(5_000).slice(0, -1)},"key0":0}`;
    const found = work(late);
    expect(found.found).toBe(true);
    expect(found.visits).toBeLessThanOrEqual(late.length);
  });

  it("deep nesting and a duplicate at the end of a large object need no recursion", () => {
    const large = keys(160_000);
    expect(hasDuplicateKey(`${large.slice(0, -1)},"key0":0}`)).toBe(true);
    expect(hasDuplicateKey("[".repeat(200_000) + "]".repeat(200_000))).toBe(false);
    expect(hasDuplicateKey('{"a":'.repeat(100_000) + "1" + "}".repeat(100_000))).toBe(false);
    expect(hasDuplicateKey(`${'{"d":'.repeat(100_000)}{"a":1,"a":2}${"}".repeat(100_000)}`)).toBe(true);
  });
});

const NOW = Date.UTC(2026, 9, 24, 12, 0, 0);
const CONFIG: ServiceConfig = {
  audience: AUDIENCE,
  corsOrigins: ["https://share.tinycloud.xyz"],
  takeOrigins: [],
  addressSalt: "strict-json-salt-0123456789",
  kill: { create: false, read: false, take: false, delete: false },
  clientAddressHeader: "CF-Connecting-IP",
};

describe("create and delete requests refuse a repeated key", () => {
  let adapter: Adapter;
  let deps: ServiceDeps;
  let counter: number;

  beforeAll(async () => {
    adapter = await createSqliteAdapter();
  });
  afterAll(async () => {
    await adapter.close();
  });
  beforeEach(async () => {
    await adapter.reset();
    counter = 0;
    deps = {
      storage: adapter.storage(),
      config: CONFIG,
      usage: { plan: WORKERS_FREE_PLAN, tally: null, statsEveryMinutes: 1 },
      now: () => NOW,
      log: () => undefined,
    };
  });

  /** Each request comes from its own address, so the address limits play no part. */
  const ip = () => `198.51.100.${(counter += 1)}`;
  const send = (url: string, text: string, method = "POST") =>
    handleRequestWithReason(new Request(url, { method, headers: { "Content-Type": "application/json", "CF-Connecting-IP": ip() }, body: text }), deps);
  const createText = async () => (await signedCreate({ issuer: makeIssuer(), nowMs: NOW })).text();
  const deleteText = async (id: string) => (await signedDelete({ issuer: makeIssuer(), id, nowMs: NOW })).text();
  const replaceOnce = (text: string, from: string, to: string) => {
    expect(text.includes(from), `request text contains ${from}`).toBe(true);
    return text.replace(from, to);
  };

  it("a request without a repeated key is accepted (create 201, delete 404 for an unknown id)", async () => {
    expect((await send(`${AUDIENCE}/v1/links`, await createText())).response.status).toBe(201);
    expect((await send(`${AUDIENCE}/v1/links/${"a".repeat(26)}/delete`, await deleteText("a".repeat(26)))).response.status).toBe(404);
  });

  const createCases: [string, (text: string) => string][] = [
    ["top level: body twice", (t) => replaceOnce(t, '"body":', '"body":"AA","body":')],
    ["top level: header twice", (t) => replaceOnce(t, '"header":', '"header":{},"header":')],
    ["header: type twice with different values", (t) => replaceOnce(t, '"type":"share"', '"type":"share","type":"courier"')],
    ["header: version twice", (t) => replaceOnce(t, '"version":1', '"version":1,"version":1')],
    ["header: a key repeated through a unicode escape", (t) => replaceOnce(t, '"type":"share"', '"type":"share","\\u0074ype":"share"')],
    ["signature: algorithm twice", (t) => replaceOnce(t, '"algorithm":"Ed25519"', '"algorithm":"Ed25519","algorithm":"Ed25519"')],
    ["signature: value twice", (t) => replaceOnce(t, '"value":"', '"value":"x","value":"')],
    ["a nested object at any depth", (t) => replaceOnce(t, '{"header":', '{"extra":{"a":{"b":1,"b":2}},"header":')],
  ];

  it.each(createCases)("create refuses a repeated key: %s", async (_name, mutate) => {
    const outcome = await send(`${AUDIENCE}/v1/links`, mutate(await createText()));
    expect(outcome.response.status).toBe(400);
    expect(await outcome.response.json()).toEqual({ error: "invalid_request" });
    expect(outcome.reason).toBe("request_shape");
  });

  const id = "b".repeat(26);
  const deleteCases: [string, (text: string) => string][] = [
    ["top level: request twice", (t) => replaceOnce(t, '"request":', '"request":{},"request":')],
    ["request: id twice", (t) => replaceOnce(t, `"id":"${id}"`, `"id":"${id}","id":"${id}"`)],
    ["request: op twice", (t) => replaceOnce(t, '"op":"delete"', '"op":"delete","op":"delete"')],
    ["signature: value twice", (t) => replaceOnce(t, '"value":"', '"value":"x","value":"')],
    ["request: a key repeated through a unicode escape", (t) => replaceOnce(t, '"op":"delete"', '"op":"delete","\\u006fp":"delete"')],
  ];

  it.each(deleteCases)("delete refuses a repeated key: %s", async (_name, mutate) => {
    const outcome = await send(`${AUDIENCE}/v1/links/${id}/delete`, mutate(await deleteText(id)));
    expect(outcome.response.status).toBe(400);
    expect(await outcome.response.json()).toEqual({ error: "invalid_request" });
    expect(outcome.reason).toBe("request_shape");
  });

  it("a refused request stores nothing and is not an internal error", async () => {
    const text = replaceOnce(await createText(), '"type":"share"', '"type":"share","type":"share"');
    const response = await handleRequest(new Request(`${AUDIENCE}/v1/links`, { method: "POST", headers: { "Content-Type": "application/json", "CF-Connecting-IP": ip() }, body: text }), deps);
    expect(response.status).toBe(400);
    expect((await adapter.driver.first<{ n: number }>("SELECT count(*) AS n FROM links", []))?.n).toBe(0);
    expect((await deps.storage.readCounts())["errors.internal"] ?? 0).toBe(0);
  });

  it("the scan runs before the block lists, the nonce set, the API key lookup, the signature check and any record write: a refused body costs only the refusal counters", async () => {
    const calls: string[] = [];
    const inner = deps.storage;
    const watched = new Proxy(inner, {
      get(target, name, receiver) {
        const value: unknown = Reflect.get(target, name, receiver);
        if (typeof value !== "function") {
          return value;
        }
        return (...args: unknown[]) => {
          calls.push(`${String(name)}${name === "hit" ? `:${String(args[0]).slice(0, 2)}` : ""}`);
          return (value as (...a: unknown[]) => unknown).apply(target, args);
        };
      },
    });
    const text = replaceOnce(await createText(), '"type":"share"', '"type":"share","type":"courier"');
    const outcome = await handleRequestWithReason(
      new Request(`${AUDIENCE}/v1/links`, { method: "POST", headers: { "Content-Type": "application/json", "CF-Connecting-IP": ip() }, body: text }),
      { ...deps, storage: watched },
    );
    expect(outcome.reason).toBe("request_shape");
    // Only the per-address refusal counter and the health counters are touched.
    expect(calls.sort()).toEqual(["count", "count", "hit:ar"]);
    for (const forbidden of ["isBlocked", "claimNonce", "apiKey", "put", "get", "take", "delete"]) {
      expect(calls).not.toContain(forbidden);
    }
  });

  it("keys that only look alike are not repeats: a Cyrillic letter in a key is an unknown field, not a repeated one", async () => {
    const outcome = await send(`${AUDIENCE}/v1/links`, replaceOnce(await createText(), '"nonce":', '"nonc\u0435":'));
    expect(outcome.response.status).toBe(400);
    expect(outcome.reason).toBe("header_fields");
  });

  it("a request that carries a client address header the same way as before still works", async () => {
    const response = await handleRequest(await signedCreate({ issuer: makeIssuer(), nowMs: NOW, ip: CLIENT_IP }), deps);
    expect(response.status).toBe(201);
  });
});
