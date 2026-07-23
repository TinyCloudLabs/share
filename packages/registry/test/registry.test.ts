import { describe, expect, it } from "vitest";
import { computeCid, generateKey, open, seal } from "@tinycloud/share-envelope";

import {
  IF_NONE_MATCH_HEADER,
  RAW_BLOCK_CONTENT_TYPE,
  fetchBlob,
  putBlob,
} from "../src/client.js";
import { CidMismatchError, RegistryHttpError } from "../src/errors.js";
import {
  DEFAULT_MAX_RETENTION_SECONDS,
  DELETE_AFTER_HEADER,
  createDevRegistry,
  type RetentionRecord,
} from "../src/dev-server.js";
import { DEV_BASE_URL, handlerFetch } from "./helpers.js";

const utf8 = new TextEncoder();

function futureIso(ms = 60_000): string {
  return new Date(Date.now() + ms).toISOString();
}

async function postBlob(
  registry: ReturnType<typeof createDevRegistry>,
  bytes: Uint8Array,
  headers: Record<string, string> = {},
): Promise<Response> {
  return registry.handler(
    new Request(`${DEV_BASE_URL}/blobs`, {
      method: "POST",
      headers: {
        "content-type": RAW_BLOCK_CONTENT_TYPE,
        [IF_NONE_MATCH_HEADER]: "*",
        [DELETE_AFTER_HEADER]: futureIso(),
        ...headers,
      },
      body: bytes as BodyInit,
      duplex: "half",
    } as RequestInit),
  );
}

describe("put -> fetch round-trip (sealed envelope, in-process)", () => {
  it("uploads a sealed blob, fetches it by CID, and the envelope opens", async () => {
    const registry = createDevRegistry();
    const fetchFn = handlerFetch(registry);
    const key = generateKey();
    const plaintext = utf8.encode(JSON.stringify({ hello: "share" }));
    const sealed = await seal(plaintext, key);

    const { cid } = await putBlob(DEV_BASE_URL, sealed.blob, futureIso(), {
      fetchFn,
    });
    expect(cid).toBe(sealed.cid);

    const fetched = await fetchBlob(DEV_BASE_URL, cid, { fetchFn });
    expect(fetched).toEqual(sealed.blob);
    // fetchBlob already re-verified the CID; the envelope also opens.
    expect(await open(fetched, key)).toEqual(plaintext);
  });
});

describe("upload endpoint", () => {
  it("rejects an oversized blob with 413", async () => {
    const registry = createDevRegistry({ maxBlobBytes: 128 });
    const response = await postBlob(registry, new Uint8Array(129));
    expect(response.status).toBe(413);
  });

  it("rejects a streamed oversized upload lacking Content-Length with 413 (bounded read)", async () => {
    const registry = createDevRegistry({ maxBlobBytes: 32 });
    const stream = new ReadableStream<Uint8Array>({
      pull(controller) {
        controller.enqueue(new Uint8Array(48));
        controller.close();
      },
    });
    const request = new Request(`${DEV_BASE_URL}/blobs`, {
      method: "POST",
      headers: {
        "content-type": RAW_BLOCK_CONTENT_TYPE,
        [IF_NONE_MATCH_HEADER]: "*",
        [DELETE_AFTER_HEADER]: futureIso(),
      },
      body: stream,
      duplex: "half",
    } as RequestInit);
    expect(request.headers.get("content-length")).toBeNull();
    const response = await registry.handler(request);
    expect(response.status).toBe(413);
  });

  it("rejects an empty body with 400", async () => {
    const registry = createDevRegistry();
    const response = await registry.handler(
      new Request(`${DEV_BASE_URL}/blobs`, {
        method: "POST",
        headers: {
          "content-type": RAW_BLOCK_CONTENT_TYPE,
          [IF_NONE_MATCH_HEADER]: "*",
          [DELETE_AFTER_HEADER]: futureIso(),
        },
      }),
    );
    expect(response.status).toBe(400);
  });

  it("is idempotent for byte-identical re-upload (create-only)", async () => {
    const registry = createDevRegistry();
    const bytes = utf8.encode("same bytes");
    const first = await postBlob(registry, bytes);
    const second = await postBlob(registry, bytes);
    expect(first.status).toBe(201);
    expect(second.status).toBe(200);
    const firstBody = (await first.json()) as { cid: string };
    const secondBody = (await second.json()) as { cid: string };
    expect(firstBody.cid).toBe(secondBody.cid);
    expect(firstBody.cid).toBe(await computeCid(bytes));
  });

  it("returns 409 if the stored bytes under a CID diverge (defensive; impossible honestly)", async () => {
    // Different bytes hash to a different CID, so this state cannot be
    // reached through the API — sha2-256 content addressing derives the key
    // from the bytes. We force store corruption to prove the check fails closed.
    const registry = createDevRegistry();
    const bytes = utf8.encode("original");
    const cid = await computeCid(bytes);
    registry.store.set(cid, {
      bytes: utf8.encode("corrupted"),
      uploadedAt: Date.now(),
      deleteAfter: Date.now() + 60_000,
    });
    const response = await postBlob(registry, bytes);
    expect(response.status).toBe(409);
  });

  it("rejects uploads missing If-None-Match: * with 428", async () => {
    const registry = createDevRegistry();
    const response = await registry.handler(
      new Request(`${DEV_BASE_URL}/blobs`, {
        method: "POST",
        headers: {
          "content-type": RAW_BLOCK_CONTENT_TYPE,
          [DELETE_AFTER_HEADER]: futureIso(),
        },
        body: utf8.encode("no precondition") as BodyInit,
      }),
    );
    expect(response.status).toBe(428);
  });

  it("rejects uploads missing x-delete-after with 400 (never default-permanent)", async () => {
    const registry = createDevRegistry();
    const response = await registry.handler(
      new Request(`${DEV_BASE_URL}/blobs`, {
        method: "POST",
        headers: {
          "content-type": RAW_BLOCK_CONTENT_TYPE,
          [IF_NONE_MATCH_HEADER]: "*",
        },
        body: utf8.encode("no retention") as BodyInit,
      }),
    );
    expect(response.status).toBe(400);
  });

  it("rejects an invalid x-delete-after with 400", async () => {
    const registry = createDevRegistry();
    const notADate = await postBlob(registry, utf8.encode("x"), {
      [DELETE_AFTER_HEADER]: "not-a-date",
    });
    expect(notADate.status).toBe(400);
    // Loosely-parseable-by-Date.parse but not strict ISO-8601 — must be rejected.
    const looseFormat = await postBlob(registry, utf8.encode("x"), {
      [DELETE_AFTER_HEADER]: "January 1, 2099",
    });
    expect(looseFormat.status).toBe(400);
    const past = await postBlob(registry, utf8.encode("x"), {
      [DELETE_AFTER_HEADER]: new Date(Date.now() - 1000).toISOString(),
    });
    expect(past.status).toBe(400);
  });

  it("rejects impossible calendar dates that Date.parse would normalize (400)", async () => {
    const registry = createDevRegistry();
    // Date.parse turns 2099-02-29 into March 1 (2099 is not a leap year).
    const feb29 = await postBlob(registry, utf8.encode("x"), {
      [DELETE_AFTER_HEADER]: "2099-02-29T00:00:00Z",
    });
    expect(feb29.status).toBe(400);
    const month13 = await postBlob(registry, utf8.encode("x"), {
      [DELETE_AFTER_HEADER]: "2099-13-01T00:00:00Z",
    });
    expect(month13.status).toBe(400);
  });

  it("accepts a valid leap date (2096-02-29)", async () => {
    const registry = createDevRegistry();
    const response = await postBlob(registry, utf8.encode("leap"), {
      [DELETE_AFTER_HEADER]: "2096-02-29T00:00:00Z",
    });
    expect(response.status).toBe(201);
  });

  it("persists the retention record atomically with the bytes", async () => {
    const registry = createDevRegistry();
    const bytes = utf8.encode("retained");
    const deleteAfter = new Date(Date.now() + 60_000);
    const response = await postBlob(registry, bytes, {
      [DELETE_AFTER_HEADER]: deleteAfter.toISOString(),
    });
    expect(response.status).toBe(201);
    const body = (await response.json()) as { cid: string; deleteAfter: string };
    expect(body.deleteAfter).toBe(deleteAfter.toISOString());
    const record = registry.store.get(await computeCid(bytes));
    expect(record).toBeDefined();
    expect((record as RetentionRecord).deleteAfter).toBe(
      deleteAfter.getTime(),
    );
    expect((record as RetentionRecord).uploadedAt).toBeGreaterThan(0);
  });

  it("clamps deleteAfter beyond the retention horizon and reports the effective value", async () => {
    const registry = createDevRegistry({ maxRetentionSeconds: 60 });
    const bytes = utf8.encode("far future retention");
    const requested = new Date(Date.now() + 3_600_000); // 1 hour, far beyond the 60s cap
    const response = await postBlob(registry, bytes, {
      [DELETE_AFTER_HEADER]: requested.toISOString(),
    });
    expect(response.status).toBe(201);
    const body = (await response.json()) as { cid: string; deleteAfter: string };
    const effective = new Date(body.deleteAfter).getTime();
    expect(effective).toBeLessThan(requested.getTime());
    expect(effective).toBeLessThanOrEqual(Date.now() + 61_000);
    const record = registry.store.get(await computeCid(bytes));
    expect((record as RetentionRecord).deleteAfter).toBe(effective);
  });

  it("uses the default 30-day retention horizon when unset", () => {
    expect(DEFAULT_MAX_RETENTION_SECONDS).toBe(30 * 24 * 60 * 60);
  });

  describe("idempotent re-upload retention reconciliation (earliest wins)", () => {
    it("keeps the existing (shorter) deleteAfter when the re-upload asks for a later one", async () => {
      const registry = createDevRegistry();
      const bytes = utf8.encode("reconcile shorter wins");
      const shorter = new Date(Date.now() + 30_000);
      const longer = new Date(Date.now() + 120_000);
      const first = await postBlob(registry, bytes, {
        [DELETE_AFTER_HEADER]: shorter.toISOString(),
      });
      expect(first.status).toBe(201);
      const second = await postBlob(registry, bytes, {
        [DELETE_AFTER_HEADER]: longer.toISOString(),
      });
      expect(second.status).toBe(200);
      const body = (await second.json()) as { deleteAfter: string };
      expect(body.deleteAfter).toBe(shorter.toISOString());
      const record = registry.store.get(await computeCid(bytes));
      expect((record as RetentionRecord).deleteAfter).toBe(shorter.getTime());
    });

    it("adopts the re-upload's (shorter) deleteAfter when it is earlier than the existing one", async () => {
      const registry = createDevRegistry();
      const bytes = utf8.encode("reconcile new shorter wins");
      const longer = new Date(Date.now() + 120_000);
      const shorter = new Date(Date.now() + 30_000);
      const first = await postBlob(registry, bytes, {
        [DELETE_AFTER_HEADER]: longer.toISOString(),
      });
      expect(first.status).toBe(201);
      const second = await postBlob(registry, bytes, {
        [DELETE_AFTER_HEADER]: shorter.toISOString(),
      });
      expect(second.status).toBe(200);
      const body = (await second.json()) as { deleteAfter: string };
      expect(body.deleteAfter).toBe(shorter.toISOString());
      const record = registry.store.get(await computeCid(bytes));
      expect((record as RetentionRecord).deleteAfter).toBe(shorter.getTime());
    });

    it("treats an expired-but-unswept record as absent: re-upload is a fresh create with exactly the new retention", async () => {
      const registry = createDevRegistry();
      const bytes = utf8.encode("expired then re-upload");
      const cid = await computeCid(bytes);
      const first = await postBlob(registry, bytes, {
        [DELETE_AFTER_HEADER]: new Date(Date.now() + 50).toISOString(),
      });
      expect(first.status).toBe(201);
      // Force-expire the record without sweeping (lazy-sweep window).
      const record = registry.store.get(cid) as RetentionRecord;
      registry.store.set(cid, { ...record, deleteAfter: Date.now() - 1_000 });
      const newDeleteAfter = new Date(Date.now() + 60_000);
      const second = await postBlob(registry, bytes, {
        [DELETE_AFTER_HEADER]: newDeleteAfter.toISOString(),
      });
      // Fresh create (201), NOT an idempotent 200 against the dead record —
      // and NOT earliest-wins reconciliation against its past deleteAfter.
      expect(second.status).toBe(201);
      const body = (await second.json()) as { deleteAfter: string };
      expect(body.deleteAfter).toBe(newDeleteAfter.toISOString());
      const stored = registry.store.get(cid) as RetentionRecord;
      expect(stored.deleteAfter).toBe(newDeleteAfter.getTime());
    });

    it("reflects the reconciled deleteAfter in Cache-Control on subsequent GETs", async () => {
      const registry = createDevRegistry();
      const bytes = utf8.encode("reconcile then fetch");
      const longer = new Date(Date.now() + 120_000);
      const shorter = new Date(Date.now() + 30_000);
      await postBlob(registry, bytes, {
        [DELETE_AFTER_HEADER]: longer.toISOString(),
      });
      await postBlob(registry, bytes, {
        [DELETE_AFTER_HEADER]: shorter.toISOString(),
      });
      const cid = await computeCid(bytes);
      const response = await registry.handler(
        new Request(`${DEV_BASE_URL}/ipfs/${cid}?format=raw`),
      );
      const cacheControl = response.headers.get("cache-control") ?? "";
      const match = /max-age=(\d+)/.exec(cacheControl);
      const maxAge = Number(match?.[1]);
      expect(maxAge).toBeLessThanOrEqual(30);
    });
  });
});

describe("createDevRegistry construction validation (fail closed)", () => {
  // Number.MAX_VALUE and MAX_SAFE_INTEGER + 1 pass Number.isInteger but
  // overflow size/retention arithmetic to Infinity, silently disabling caps.
  it.each([
    Number.NaN,
    Number.POSITIVE_INFINITY,
    0,
    -1,
    1.5,
    Number.MAX_VALUE,
    Number.MAX_SAFE_INTEGER + 1,
  ])("rejects maxBlobBytes=%s", (maxBlobBytes) => {
    expect(() => createDevRegistry({ maxBlobBytes })).toThrow(TypeError);
  });

  it.each([
    Number.NaN,
    Number.POSITIVE_INFINITY,
    0,
    -1,
    1.5,
    Number.MAX_VALUE,
    Number.MAX_SAFE_INTEGER + 1,
  ])("rejects maxRetentionSeconds=%s", (maxRetentionSeconds) => {
    expect(() => createDevRegistry({ maxRetentionSeconds })).toThrow(
      TypeError,
    );
  });
});

describe("gateway endpoint (trustless response shape)", () => {
  it("serves ?format=raw with application/vnd.ipld.raw", async () => {
    const registry = createDevRegistry();
    const bytes = utf8.encode("gateway bytes");
    await postBlob(registry, bytes);
    const cid = await computeCid(bytes);
    const response = await registry.handler(
      new Request(`${DEV_BASE_URL}/ipfs/${cid}?format=raw`),
    );
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toBe(RAW_BLOCK_CONTENT_TYPE);
    expect(new Uint8Array(await response.arrayBuffer())).toEqual(bytes);
  });

  it("accepts the raw Accept header in place of ?format=raw", async () => {
    const registry = createDevRegistry();
    const bytes = utf8.encode("accept header");
    await postBlob(registry, bytes);
    const cid = await computeCid(bytes);
    const response = await registry.handler(
      new Request(`${DEV_BASE_URL}/ipfs/${cid}`, {
        headers: { accept: RAW_BLOCK_CONTENT_TYPE },
      }),
    );
    expect(response.status).toBe(200);
  });

  it("returns 406 without ?format=raw or a raw Accept header", async () => {
    const registry = createDevRegistry();
    const bytes = utf8.encode("no format");
    await postBlob(registry, bytes);
    const cid = await computeCid(bytes);
    const response = await registry.handler(
      new Request(`${DEV_BASE_URL}/ipfs/${cid}`),
    );
    expect(response.status).toBe(406);
  });

  it("returns 406 when Accept carries the raw type at q=0 (not acceptable)", async () => {
    const registry = createDevRegistry();
    const bytes = utf8.encode("q0 not acceptable");
    await postBlob(registry, bytes);
    const cid = await computeCid(bytes);
    const response = await registry.handler(
      new Request(`${DEV_BASE_URL}/ipfs/${cid}`, {
        headers: { accept: `${RAW_BLOCK_CONTENT_TYPE};q=0` },
      }),
    );
    expect(response.status).toBe(406);
  });

  it("returns 406 when Accept carries the raw type at Q=0 (q is case-insensitive, RFC 9110)", async () => {
    const registry = createDevRegistry();
    const bytes = utf8.encode("uppercase Q0 not acceptable");
    await postBlob(registry, bytes);
    const cid = await computeCid(bytes);
    const response = await registry.handler(
      new Request(`${DEV_BASE_URL}/ipfs/${cid}`, {
        headers: { accept: `${RAW_BLOCK_CONTENT_TYPE};Q=0` },
      }),
    );
    expect(response.status).toBe(406);
  });

  it("returns 406 for a malformed q value (fail closed, not assumed acceptable)", async () => {
    const registry = createDevRegistry();
    const bytes = utf8.encode("bogus q not acceptable");
    await postBlob(registry, bytes);
    const cid = await computeCid(bytes);
    const response = await registry.handler(
      new Request(`${DEV_BASE_URL}/ipfs/${cid}`, {
        headers: { accept: `${RAW_BLOCK_CONTENT_TYPE};q=bogus` },
      }),
    );
    expect(response.status).toBe(406);
  });

  it("accepts a valid fractional q on the raw type (q=0.5)", async () => {
    const registry = createDevRegistry();
    const bytes = utf8.encode("q=0.5 acceptable");
    await postBlob(registry, bytes);
    const cid = await computeCid(bytes);
    const response = await registry.handler(
      new Request(`${DEV_BASE_URL}/ipfs/${cid}`, {
        headers: { accept: `${RAW_BLOCK_CONTENT_TYPE};q=0.5` },
      }),
    );
    expect(response.status).toBe(200);
  });

  it("?format=raw takes precedence over a q=0 Accept header", async () => {
    const registry = createDevRegistry();
    const bytes = utf8.encode("format wins over q0");
    await postBlob(registry, bytes);
    const cid = await computeCid(bytes);
    const response = await registry.handler(
      new Request(`${DEV_BASE_URL}/ipfs/${cid}?format=raw`, {
        headers: { accept: `${RAW_BLOCK_CONTENT_TYPE};q=0` },
      }),
    );
    expect(response.status).toBe(200);
  });

  it("an explicit non-raw ?format= is 406 even with a fully-acceptable raw Accept header", async () => {
    const registry = createDevRegistry();
    const bytes = utf8.encode("format conflict, format wins");
    await postBlob(registry, bytes);
    const cid = await computeCid(bytes);
    const response = await registry.handler(
      new Request(`${DEV_BASE_URL}/ipfs/${cid}?format=car`, {
        headers: { accept: RAW_BLOCK_CONTENT_TYPE },
      }),
    );
    expect(response.status).toBe(406);
  });

  it("serves /blobs/<cid> as an alias with the same content-type", async () => {
    const registry = createDevRegistry();
    const bytes = utf8.encode("alias");
    await postBlob(registry, bytes);
    const cid = await computeCid(bytes);
    const response = await registry.handler(
      new Request(`${DEV_BASE_URL}/blobs/${cid}`),
    );
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toBe(RAW_BLOCK_CONTENT_TYPE);
  });

  it("returns 404 for an unknown CID", async () => {
    const registry = createDevRegistry();
    const cid = await computeCid(utf8.encode("never uploaded"));
    const response = await registry.handler(
      new Request(`${DEV_BASE_URL}/ipfs/${cid}?format=raw`),
    );
    expect(response.status).toBe(404);
  });

  it("bounds Cache-Control max-age by deleteAfter", async () => {
    const registry = createDevRegistry();
    const bytes = utf8.encode("bounded cache");
    await postBlob(registry, bytes, {
      [DELETE_AFTER_HEADER]: new Date(Date.now() + 120_000).toISOString(),
    });
    const cid = await computeCid(bytes);
    const response = await registry.handler(
      new Request(`${DEV_BASE_URL}/ipfs/${cid}?format=raw`),
    );
    const cacheControl = response.headers.get("cache-control") ?? "";
    const match = /max-age=(\d+)/.exec(cacheControl);
    expect(match).not.toBeNull();
    const maxAge = Number(match?.[1]);
    expect(maxAge).toBeGreaterThan(0);
    expect(maxAge).toBeLessThanOrEqual(120);
    expect(cacheControl).toContain("immutable");
  });
});

describe("expiry (dev stand-in for pin rm + gc)", () => {
  it("sweepExpired drops expired entries and GET 404s afterwards", async () => {
    const registry = createDevRegistry();
    const bytes = utf8.encode("expiring");
    await postBlob(registry, bytes, {
      [DELETE_AFTER_HEADER]: new Date(Date.now() + 50).toISOString(),
    });
    const cid = await computeCid(bytes);
    expect(registry.sweepExpired(Date.now() + 60_000)).toBe(1);
    expect(registry.store.has(cid)).toBe(false);
    const response = await registry.handler(
      new Request(`${DEV_BASE_URL}/ipfs/${cid}?format=raw`),
    );
    expect(response.status).toBe(404);
  });

  it("GET checks expiry even without a sweep", async () => {
    const registry = createDevRegistry();
    const bytes = utf8.encode("lazy expiry");
    const cid = await computeCid(bytes);
    registry.store.set(cid, {
      bytes,
      uploadedAt: Date.now() - 10_000,
      deleteAfter: Date.now() - 1,
    });
    const response = await registry.handler(
      new Request(`${DEV_BASE_URL}/ipfs/${cid}?format=raw`),
    );
    expect(response.status).toBe(404);
    expect(registry.store.has(cid)).toBe(false);
  });
});

describe("lying gateway (tamper injection)", () => {
  it("client throws CidMismatchError when the store serves wrong bytes for a CID", async () => {
    const registry = createDevRegistry();
    const fetchFn = handlerFetch(registry);
    const sealed = await seal(utf8.encode("honest"), generateKey());
    const { cid } = await putBlob(DEV_BASE_URL, sealed.blob, futureIso(), {
      fetchFn,
    });

    // The gateway lies: same CID, substituted bytes.
    registry.store.set(cid, {
      bytes: utf8.encode("substituted by a lying gateway"),
      uploadedAt: Date.now(),
      deleteAfter: Date.now() + 60_000,
    });

    await expect(fetchBlob(DEV_BASE_URL, cid, { fetchFn })).rejects.toBeInstanceOf(
      CidMismatchError,
    );
  });

  it("client fails closed on a 404 from the registry", async () => {
    const registry = createDevRegistry();
    const fetchFn = handlerFetch(registry);
    const cid = await computeCid(utf8.encode("missing"));
    await expect(fetchBlob(DEV_BASE_URL, cid, { fetchFn })).rejects.toBeInstanceOf(
      RegistryHttpError,
    );
  });
});
