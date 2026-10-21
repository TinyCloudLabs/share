import { describe, expect, it } from "vitest";
import { setTimeout as sleep } from "node:timers/promises";
import vectorsJson from "./fixtures/shortlink-vectors.json";
import {
  canonicalShortLinkExpiry,
  publishShortLinkOrInline,
  revokeStoredShortLink,
  SHORT_LINK_UNAVAILABLE_NOTICE,
  shortLinkRecordPath,
} from "../src/short-links/publish.js";

interface Vector {
  readonly inline: string;
  readonly id: string;
  readonly ciphertextB64Url: string;
  readonly cid: string;
  readonly k: string;
  readonly short: string;
}

const vector = (vectorsJson as readonly Vector[])[0]!;
const DAY_MS = 24 * 60 * 60 * 1000;
const futureExpiry = (ms: number): string => new Date(Date.now() + ms).toISOString();

interface Call {
  readonly url: string;
  readonly init: RequestInit;
}

function recordingFetch(respond: (call: Call) => Response | Promise<Response>): { fetchFn: typeof fetch; calls: Call[] } {
  const calls: Call[] = [];
  const fetchFn = (async (url: string, init: RequestInit) => {
    const call = { url, init };
    calls.push(call);
    return respond(call);
  }) as typeof fetch;
  return { fetchFn, calls };
}

const created = (overrides: Record<string, unknown> = {}): Response =>
  new Response(JSON.stringify({ id: vector.id, cid: vector.cid, deleteToken: "tok", ...overrides }), {
    status: 201,
    headers: { "content-type": "application/json" },
  });

const ok = (): Response => new Response(null, { status: 204 });

function publish(overrides: Partial<Parameters<typeof publishShortLinkOrInline>[0]> = {}) {
  const stored: Array<{ id: string; deleteToken: string }> = [];
  const { fetchFn, calls } = recordingFetch(() => created());
  const input = {
    inlineUrl: vector.inline,
    material: { sealedEnvelope: vector.ciphertextB64Url, shareCid: vector.cid },
    expiresAt: futureExpiry(3 * DAY_MS),
    storeRecord: async (record: { id: string; deleteToken: string }) => {
      stored.push(record);
    },
    fetchFn,
    ...overrides,
  };
  return { run: () => publishShortLinkOrInline(input), stored, calls };
}

describe("publishShortLinkOrInline", () => {
  it("returns the short link and stores the delete record when the service accepts it", async () => {
    const { run, stored } = publish();

    const result = await run();

    expect(result).toEqual({ url: vector.short });
    expect(stored).toEqual([{ id: vector.id, deleteToken: "tok" }]);
  });

  it("posts only the sealed bytes and canonical UTC expiry, never the key", async () => {
    const { run, calls } = publish();

    await run();

    const body = String(calls[0]!.init.body);
    expect(JSON.parse(body)).toEqual({ ciphertext: vector.ciphertextB64Url, expiresAt: expect.stringMatching(/Z$/) });
    expect(body).not.toContain(vector.k);
  });

  it.each([
    ["a CID that does not match the inline link", () => created({ cid: "bafkreiotherothertherotherotherotherotherotherother" })],
  ])("falls back to the inline link with a notice and deletes the created link on %s", async (_label, respond) => {
    const { fetchFn, calls } = recordingFetch((call) => (call.init.method === "DELETE" ? ok() : respond()));
    const stored: unknown[] = [];

    const result = await publishShortLinkOrInline({
      inlineUrl: vector.inline,
      material: { sealedEnvelope: vector.ciphertextB64Url, shareCid: vector.cid },
      expiresAt: futureExpiry(3 * DAY_MS),
      storeRecord: async (record) => {
        stored.push(record);
      },
      fetchFn,
    });

    expect(result).toEqual({ url: vector.inline, notice: SHORT_LINK_UNAVAILABLE_NOTICE });
    expect(stored).toHaveLength(0);
    expect(calls.map((call) => call.init.method)).toEqual(["POST", "DELETE"]);
    expect(new Headers(calls[1]!.init.headers).get("authorization")).toBe("Bearer tok");
  });

  it.each([429, 503, 500, 400])("falls back to the inline link on HTTP %i without a delete, since nothing was created", async (status) => {
    const { fetchFn, calls } = recordingFetch(() => new Response(null, { status }));
    const stored: unknown[] = [];
    const result = await publishShortLinkOrInline({
      inlineUrl: vector.inline,
      material: { sealedEnvelope: vector.ciphertextB64Url, shareCid: vector.cid },
      expiresAt: futureExpiry(3 * DAY_MS),
      storeRecord: async (record) => {
        stored.push(record);
      },
      fetchFn,
    });

    expect(result).toEqual({ url: vector.inline, notice: SHORT_LINK_UNAVAILABLE_NOTICE });
    expect(stored).toHaveLength(0);
    expect(calls.map((call) => call.init.method)).toEqual(["POST"]);
  });

  it("falls back to the inline link on a network failure", async () => {
    const { run, stored } = publish({ fetchFn: (() => Promise.reject(new TypeError("offline"))) as typeof fetch });

    const result = await run();

    expect(result).toEqual({ url: vector.inline, notice: SHORT_LINK_UNAVAILABLE_NOTICE });
    expect(stored).toHaveLength(0);
  });

  it("falls back to the inline link when the service does not answer within the timeout", async () => {
    const { run } = publish({
      timeoutMs: 5,
      fetchFn: (async (_url: string, init: RequestInit) => {
        await sleep(60_000, undefined, { signal: init.signal ?? undefined });
        return new Response(null, { status: 201 });
      }) as typeof fetch,
    });

    expect(await run()).toEqual({ url: vector.inline, notice: SHORT_LINK_UNAVAILABLE_NOTICE });
  });

  it("deletes the created link and falls back when the delete record cannot be stored", async () => {
    const { fetchFn, calls } = recordingFetch((call) => (call.init.method === "DELETE" ? ok() : created()));

    const result = await publishShortLinkOrInline({
      inlineUrl: vector.inline,
      material: { sealedEnvelope: vector.ciphertextB64Url, shareCid: vector.cid },
      expiresAt: futureExpiry(3 * DAY_MS),
      storeRecord: async () => {
        throw new Error("kv down");
      },
      fetchFn,
    });

    expect(result).toEqual({ url: vector.inline, notice: SHORT_LINK_UNAVAILABLE_NOTICE });
    expect(calls.map((call) => call.init.method)).toEqual(["POST", "DELETE"]);
  });

  it("does not call the service when the expiry is under 120 seconds away", async () => {
    const { run, calls } = publish({ expiresAt: futureExpiry(60_000) });

    expect(await run()).toEqual({ url: vector.inline, notice: SHORT_LINK_UNAVAILABLE_NOTICE });
    expect(calls).toHaveLength(0);
  });

  it("does not call the service when the expiry is over 400 days away", async () => {
    const { run, calls } = publish({ expiresAt: futureExpiry(401 * DAY_MS) });

    expect(await run()).toEqual({ url: vector.inline, notice: SHORT_LINK_UNAVAILABLE_NOTICE });
    expect(calls).toHaveLength(0);
  });

  it("does not call the service when the share has no expiry", async () => {
    const { run, calls } = publish({ expiresAt: undefined });

    expect(await run()).toEqual({ url: vector.inline, notice: SHORT_LINK_UNAVAILABLE_NOTICE });
    expect(calls).toHaveLength(0);
  });
});

describe("canonicalShortLinkExpiry", () => {
  const now = Date.parse("2026-01-01T00:00:00.000Z");

  it("accepts exactly 120 seconds and returns canonical UTC milliseconds", () => {
    expect(canonicalShortLinkExpiry("2026-01-01T00:02:00.000Z", now)).toBe("2026-01-01T00:02:00.000Z");
  });

  it("rejects anything under 120 seconds away", () => {
    expect(() => canonicalShortLinkExpiry("2026-01-01T00:01:59.999Z", now)).toThrow();
  });

  it("rejects anything over 400 days away", () => {
    expect(() => canonicalShortLinkExpiry(new Date(now + 400 * DAY_MS + 1).toISOString(), now)).toThrow();
  });

  it("rejects an unparseable expiry", () => {
    expect(() => canonicalShortLinkExpiry("not a date", now)).toThrow();
  });
});

describe("revokeStoredShortLink", () => {
  const kvWith = (value: unknown) => ({
    get: async () => ({ ok: true, data: { data: value } }),
  });

  it("reads the record at the share's record path and deletes the short link", async () => {
    const reads: string[] = [];
    const kv = {
      get: async (key: string) => {
        reads.push(key);
        return { ok: true, data: { data: JSON.stringify({ id: vector.id, deleteToken: "tok" }) } };
      },
    };
    const { fetchFn, calls } = recordingFetch(() => ok());

    expect(await revokeStoredShortLink({ shareId: "share-1", kv, fetchFn })).toBe("deleted");
    expect(reads).toEqual([shortLinkRecordPath("share-1")]);
    expect(calls).toHaveLength(1);
    expect(calls[0]!.url).toBe(`/api/share-links/${vector.id}`);
    expect(new Headers(calls[0]!.init.headers).get("authorization")).toBe("Bearer tok");
  });

  it("reads a record stored as bytes", async () => {
    const bytes = new TextEncoder().encode(JSON.stringify({ id: vector.id, deleteToken: "tok" }));
    const { fetchFn, calls } = recordingFetch(() => ok());

    expect(await revokeStoredShortLink({ shareId: "share-1", kv: kvWith(bytes), fetchFn })).toBe("deleted");
    expect(calls).toHaveLength(1);
  });

  it("keeps the record when the DELETE fails so the next revoke can retry it", async () => {
    const { fetchFn, calls } = recordingFetch(() => new Response(null, { status: 500 }));

    expect(await revokeStoredShortLink({ shareId: "share-1", kv: kvWith(JSON.stringify({ id: vector.id, deleteToken: "tok" })), fetchFn })).toBe(
      "kept",
    );
    expect(calls).toHaveLength(1);
  });

  it("returns none for a share with no record, so older inline-only shares are untouched", async () => {
    const kv = { get: async () => ({ ok: false }) };
    const { fetchFn, calls } = recordingFetch(() => ok());

    expect(await revokeStoredShortLink({ shareId: "share-1", kv, fetchFn })).toBe("none");
    expect(calls).toHaveLength(0);
  });

  it("returns none for a malformed record without sending a DELETE", async () => {
    const { fetchFn, calls } = recordingFetch(() => ok());

    expect(await revokeStoredShortLink({ shareId: "share-1", kv: kvWith("{not json"), fetchFn })).toBe("none");
    expect(calls).toHaveLength(0);
  });
});
