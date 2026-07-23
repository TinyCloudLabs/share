import { describe, expect, it, vi } from "vitest";
import { computeCid } from "@tinycloud/share-envelope";

import {
  DEFAULT_MAX_BLOB_BYTES,
  RAW_BLOCK_CONTENT_TYPE,
  fetchBlob,
  putBlob,
} from "../src/client.js";
import {
  BlobTooLargeError,
  CidMismatchError,
  RegistryHttpError,
} from "../src/errors.js";

const BASE = "http://registry.local";

function futureDeleteAfter(ms = 60_000): string {
  return new Date(Date.now() + ms).toISOString();
}

function stubFetch(response: Response): typeof fetch {
  return vi.fn(async () => response) as unknown as typeof fetch;
}

describe("putBlob (client-side guards)", () => {
  it("rejects an oversized blob before any network call", async () => {
    const neverCalled = vi.fn();
    const blob = new Uint8Array(DEFAULT_MAX_BLOB_BYTES + 1);
    await expect(
      putBlob(BASE, blob, futureDeleteAfter(), {
        fetchFn: neverCalled as unknown as typeof fetch,
      }),
    ).rejects.toBeInstanceOf(BlobTooLargeError);
    expect(neverCalled).not.toHaveBeenCalled();
  });

  it("respects a custom maxBlobBytes cap", async () => {
    const neverCalled = vi.fn();
    await expect(
      putBlob(BASE, new Uint8Array(11), futureDeleteAfter(), {
        maxBlobBytes: 10,
        fetchFn: neverCalled as unknown as typeof fetch,
      }),
    ).rejects.toBeInstanceOf(BlobTooLargeError);
    expect(neverCalled).not.toHaveBeenCalled();
  });

  it("requires deleteAfter and fails closed when it is missing", async () => {
    const neverCalled = vi.fn();
    await expect(
      putBlob(
        BASE,
        new Uint8Array([1]),
        undefined as unknown as string,
        { fetchFn: neverCalled as unknown as typeof fetch },
      ),
    ).rejects.toThrow(TypeError);
    expect(neverCalled).not.toHaveBeenCalled();
  });

  it("rejects an invalid Date deleteAfter", async () => {
    const neverCalled = vi.fn();
    await expect(
      putBlob(BASE, new Uint8Array([1]), new Date(Number.NaN), {
        fetchFn: neverCalled as unknown as typeof fetch,
      }),
    ).rejects.toThrow(TypeError);
    expect(neverCalled).not.toHaveBeenCalled();
  });

  // Number.MAX_VALUE and MAX_SAFE_INTEGER + 1 pass Number.isInteger but
  // overflow size arithmetic to Infinity, silently disabling the cap.
  it.each([
    Number.NaN,
    Number.POSITIVE_INFINITY,
    0,
    -1,
    1.5,
    Number.MAX_VALUE,
    Number.MAX_SAFE_INTEGER + 1,
  ])("rejects maxBlobBytes=%s at call time", async (maxBlobBytes) => {
    const neverCalled = vi.fn();
    await expect(
      putBlob(BASE, new Uint8Array([1]), futureDeleteAfter(), {
        maxBlobBytes,
        fetchFn: neverCalled as unknown as typeof fetch,
      }),
    ).rejects.toBeInstanceOf(TypeError);
    expect(neverCalled).not.toHaveBeenCalled();
  });

  it("sends If-None-Match: * and x-delete-after on upload", async () => {
    const deleteAfter = futureDeleteAfter();
    const cid = await computeCid(new Uint8Array([1, 2, 3]));
    const fetchFn = vi.fn(async () =>
      new Response(JSON.stringify({ cid, deleteAfter }), {
        status: 201,
        headers: { "content-type": "application/json" },
      }),
    ) as unknown as typeof fetch;
    await putBlob(BASE, new Uint8Array([1, 2, 3]), deleteAfter, { fetchFn });
    const call = (fetchFn as unknown as ReturnType<typeof vi.fn>).mock
      .calls[0] as [string, RequestInit];
    const headers = new Headers(call[1].headers);
    expect(headers.get("if-none-match")).toBe("*");
    expect(headers.get("x-delete-after")).toBe(deleteAfter);
  });

  it("returns the effective deleteAfter from the response", async () => {
    const bytes = new Uint8Array([1, 2, 3]);
    const cid = await computeCid(bytes);
    const effective = futureDeleteAfter(30_000);
    const fetchFn = stubFetch(
      new Response(JSON.stringify({ cid, deleteAfter: effective }), {
        status: 201,
        headers: { "content-type": "application/json" },
      }),
    );
    const result = await putBlob(BASE, bytes, futureDeleteAfter(), {
      fetchFn,
    });
    expect(result).toEqual({ cid, deleteAfter: effective });
  });

  it("throws RegistryHttpError when the response body has no deleteAfter", async () => {
    const bytes = new Uint8Array([1, 2, 3]);
    const cid = await computeCid(bytes);
    const fetchFn = stubFetch(
      new Response(JSON.stringify({ cid }), {
        status: 201,
        headers: { "content-type": "application/json" },
      }),
    );
    await expect(
      putBlob(BASE, bytes, futureDeleteAfter(), { fetchFn }),
    ).rejects.toBeInstanceOf(RegistryHttpError);
  });

  it("throws CidMismatchError when the server claims a different CID", async () => {
    const fetchFn = stubFetch(
      new Response(
        JSON.stringify({ cid: "bafkreiliar", deleteAfter: futureDeleteAfter() }),
        {
          status: 201,
          headers: { "content-type": "application/json" },
        },
      ),
    );
    await expect(
      putBlob(BASE, new Uint8Array([1, 2, 3]), futureDeleteAfter(), {
        fetchFn,
      }),
    ).rejects.toBeInstanceOf(CidMismatchError);
  });

  it("throws RegistryHttpError on non-2xx", async () => {
    const fetchFn = stubFetch(new Response("nope", { status: 500 }));
    const error = await putBlob(
      BASE,
      new Uint8Array([1]),
      futureDeleteAfter(),
      { fetchFn },
    ).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(RegistryHttpError);
    expect((error as RegistryHttpError).status).toBe(500);
  });

  it("throws RegistryHttpError when the response body has no cid", async () => {
    const fetchFn = stubFetch(
      new Response(JSON.stringify({ ok: true }), { status: 201 }),
    );
    await expect(
      putBlob(BASE, new Uint8Array([1]), futureDeleteAfter(), { fetchFn }),
    ).rejects.toBeInstanceOf(RegistryHttpError);
  });
});

describe("fetchBlob (client-side guards)", () => {
  it("throws RegistryHttpError on non-2xx", async () => {
    const bytes = new Uint8Array([1, 2, 3]);
    const cid = await computeCid(bytes);
    const fetchFn = stubFetch(new Response("gone", { status: 404 }));
    const error = await fetchBlob(BASE, cid, { fetchFn }).catch(
      (e: unknown) => e,
    );
    expect(error).toBeInstanceOf(RegistryHttpError);
    expect((error as RegistryHttpError).status).toBe(404);
  });

  it("throws RegistryHttpError on wrong content-type even with correct bytes", async () => {
    const bytes = new Uint8Array([1, 2, 3]);
    const cid = await computeCid(bytes);
    const fetchFn = stubFetch(
      new Response(bytes, {
        status: 200,
        headers: { "content-type": "text/plain" },
      }),
    );
    await expect(fetchBlob(BASE, cid, { fetchFn })).rejects.toBeInstanceOf(
      RegistryHttpError,
    );
  });

  it("throws CidMismatchError when the gateway returns wrong bytes", async () => {
    const cid = await computeCid(new Uint8Array([1, 2, 3]));
    const fetchFn = stubFetch(
      new Response(new Uint8Array([9, 9, 9]), {
        status: 200,
        headers: { "content-type": RAW_BLOCK_CONTENT_TYPE },
      }),
    );
    await expect(fetchBlob(BASE, cid, { fetchFn })).rejects.toBeInstanceOf(
      CidMismatchError,
    );
  });

  it("rejects an oversized response body declared via Content-Length before reading it", async () => {
    const bytes = new Uint8Array(64);
    const cid = await computeCid(bytes);
    const fetchFn = stubFetch(
      new Response(bytes, {
        status: 200,
        headers: {
          "content-type": RAW_BLOCK_CONTENT_TYPE,
          "content-length": "64",
        },
      }),
    );
    await expect(
      fetchBlob(BASE, cid, { fetchFn, maxBlobBytes: 32 }),
    ).rejects.toBeInstanceOf(BlobTooLargeError);
  });

  it("aborts a streamed oversized body without Content-Length", async () => {
    const cid = await computeCid(new Uint8Array(64));
    let cancelled = false;
    const stream = new ReadableStream<Uint8Array>({
      pull(controller) {
        controller.enqueue(new Uint8Array(48));
      },
      cancel() {
        cancelled = true;
      },
    });
    const response = new Response(stream, {
      status: 200,
      headers: { "content-type": RAW_BLOCK_CONTENT_TYPE },
    });
    // Undici sets Content-Length automatically for buffer-backed bodies but
    // not for arbitrary streams, so this exercises the streaming path.
    expect(response.headers.get("content-length")).toBeNull();
    const fetchFn = stubFetch(response);
    await expect(
      fetchBlob(BASE, cid, { fetchFn, maxBlobBytes: 32 }),
    ).rejects.toBeInstanceOf(BlobTooLargeError);
    expect(cancelled).toBe(true);
  });

  it.each([
    Number.NaN,
    Number.POSITIVE_INFINITY,
    0,
    -1,
    1.5,
    Number.MAX_VALUE,
    Number.MAX_SAFE_INTEGER + 1,
  ])("rejects maxBlobBytes=%s at call time", async (maxBlobBytes) => {
    const cid = await computeCid(new Uint8Array([1]));
    const neverCalled = vi.fn();
    await expect(
      fetchBlob(BASE, cid, {
        maxBlobBytes,
        fetchFn: neverCalled as unknown as typeof fetch,
      }),
    ).rejects.toBeInstanceOf(TypeError);
    expect(neverCalled).not.toHaveBeenCalled();
  });

  it.each([
    "not-a-cid",
    "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG", // CIDv0 (base58btc, dag-pb)
    "", // empty
  ])("rejects malformed/CIDv0 cid %j before any network call", async (badCid) => {
    const neverCalled = vi.fn();
    await expect(
      fetchBlob(BASE, badCid, {
        fetchFn: neverCalled as unknown as typeof fetch,
      }),
    ).rejects.toBeInstanceOf(TypeError);
    expect(neverCalled).not.toHaveBeenCalled();
  });

  it("rejects an uppercase re-encoding of a valid CID before any network call", async () => {
    const validCid = await computeCid(new Uint8Array([1, 2, 3]));
    const uppercased = validCid.toUpperCase();
    const neverCalled = vi.fn();
    await expect(
      fetchBlob(BASE, uppercased, {
        fetchFn: neverCalled as unknown as typeof fetch,
      }),
    ).rejects.toBeInstanceOf(TypeError);
    expect(neverCalled).not.toHaveBeenCalled();
  });
});
