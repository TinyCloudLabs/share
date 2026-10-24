import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import type { D1Database } from "../src/d1-driver.ts";
import worker from "../src/worker.ts";
import { get } from "./support/client.ts";

const SALT = "config-error-salt-0123456789";
const NODE = "did:key:z6Mkg49NtQR2LyYRDCQFK4w1VVHqhypZSSRo7HsyuN7SV7v5";

/** The database is never reached when the configuration is refused. */
const unreachableDb: D1Database = {
  prepare: () => {
    throw new Error("the database is not used");
  },
  batch: () => {
    throw new Error("the database is not used");
  },
};

describe("a Worker whose configuration is refused", () => {
  const ctx = { waitUntil: () => undefined };
  const cases: [string, Record<string, unknown>][] = [
    ["a malformed LINKS_READ_SIGNERS", { DB: unreachableDb, ADDRESS_SALT: SALT, LINKS_READ_SIGNERS: "{not json" }],
    ["a label that is not service:<name>", { DB: unreachableDb, ADDRESS_SALT: SALT, LINKS_READ_SIGNERS: JSON.stringify([{ label: "node", did: NODE }]) }],
    ["a missing ADDRESS_SALT", { DB: unreachableDb }],
    ["a bad LINKS_READ_AUTH_LIMIT", { DB: unreachableDb, ADDRESS_SALT: SALT, LINKS_READ_AUTH_LIMIT: "0" }],
  ];

  it.each(cases)("answers %s with a 500 that carries a Date header from the Worker clock", async (_name, env) => {
    const before = Date.now();
    const response = await worker.fetch(get("a".repeat(26)), env as unknown as Parameters<typeof worker.fetch>[1], ctx);
    const after = Date.now();
    expect(response.status).toBe(500);
    expect(await response.json()).toEqual({ error: "internal" });
    const date = response.headers.get("Date");
    expect(date).not.toBeNull();
    const stamped = Date.parse(date ?? "");
    // The header has one-second resolution.
    expect(stamped).toBeGreaterThanOrEqual(before - 1_000);
    expect(stamped).toBeLessThanOrEqual(after + 1_000);
  });

  it("keeps the headers every response carries", async () => {
    const response = await worker.fetch(get("a".repeat(26)), cases[0]?.[1] as unknown as Parameters<typeof worker.fetch>[1], ctx);
    expect(response.headers.get("Cache-Control")).toBe("no-store");
    expect(response.headers.get("X-Content-Type-Options")).toBe("nosniff");
    expect(response.headers.get("Content-Type")).toBe("application/json");
  });
});

describe("LAUNCH-CHECKLIST.md", () => {
  const text = readFileSync(new URL("../LAUNCH-CHECKLIST.md", import.meta.url), "utf8");

  it("asks for the missing-line and 5xx alerts before email is enabled", () => {
    expect(text).toMatch(/Before email is enabled:/);
    expect(text).toMatch(/alert on a missing `links\.health` line/);
    expect(text).toMatch(/any 5xx rate above zero/);
    expect(text).toMatch(/BEFORE email is enabled/);
  });

  it("says what to do when LINKS_READ_SIGNERS makes every request answer 500", () => {
    expect(text).toMatch(/Set `LINKS_READ_SIGNERS` only with an immediate smoke/);
    expect(text).toMatch(/the first action is to unset it/);
  });
});
