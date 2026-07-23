import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { generateKey, seal } from "@tinycloud/share-envelope";

import { fetchBlob, putBlob } from "../src/client.js";
import { serveDevRegistry, type DevRegistryServer } from "../src/dev-server.js";

function futureIso(ms = 60_000): string {
  return new Date(Date.now() + ms).toISOString();
}

// One real node:http round-trip so the CLI-facing adapter (listen(), body
// streaming, header mapping) is exercised over an actual socket.
describe("serveDevRegistry (real node:http listener)", () => {
  let running: DevRegistryServer;

  beforeAll(async () => {
    running = await serveDevRegistry({ port: 0, maxBlobBytes: 4096 });
  });

  afterAll(async () => {
    await running.close();
  });

  it("round-trips a sealed blob over a real socket with global fetch", async () => {
    const sealed = await seal(new TextEncoder().encode("over the wire"), generateKey());
    const { cid } = await putBlob(running.url, sealed.blob, futureIso());
    expect(cid).toBe(sealed.cid);
    const fetched = await fetchBlob(running.url, cid);
    expect(fetched).toEqual(sealed.blob);
  });

  it("cuts off an oversized upload with 413", async () => {
    const response = await fetch(`${running.url}/blobs`, {
      method: "POST",
      headers: {
        "content-type": "application/vnd.ipld.raw",
        "if-none-match": "*",
        "x-delete-after": futureIso(),
      },
      body: new Uint8Array(8192),
    });
    expect(response.status).toBe(413);
  });
});

describe("serveDevRegistry onError (fix: observable internal errors)", () => {
  it("invokes onError and still returns a generic 500 when the handler throws", async () => {
    const onError = vi.fn();
    const running = await serveDevRegistry({ port: 0, onError });
    try {
      const boom = new Error("boom");
      running.registry.handler = () => Promise.reject(boom);
      const response = await fetch(`${running.url}/blobs`, {
        method: "POST",
        headers: {
          "content-type": "application/vnd.ipld.raw",
          "if-none-match": "*",
          "x-delete-after": futureIso(),
        },
        body: new Uint8Array([1, 2, 3]),
      });
      expect(response.status).toBe(500);
      const body = (await response.json()) as { error: string };
      expect(body).toEqual({ error: "internal error" });
      expect(onError).toHaveBeenCalledWith(boom);
    } finally {
      await running.close();
    }
  });

  it("routes a SYNCHRONOUS handler throw through onError with a generic 500", async () => {
    // A sync throw from `new Request(...)` / `registry.handler(...)` used to
    // escape the promise .catch entirely; the whole per-request body must be
    // wrapped so sync and async throws behave identically.
    const onError = vi.fn();
    const running = await serveDevRegistry({ port: 0, onError });
    try {
      const boom = new Error("sync boom");
      running.registry.handler = () => {
        throw boom;
      };
      const response = await fetch(`${running.url}/blobs`, {
        method: "POST",
        headers: {
          "content-type": "application/vnd.ipld.raw",
          "if-none-match": "*",
          "x-delete-after": futureIso(),
        },
        body: new Uint8Array([1, 2, 3]),
      });
      expect(response.status).toBe(500);
      const body = (await response.json()) as { error: string };
      expect(body).toEqual({ error: "internal error" });
      expect(onError).toHaveBeenCalledWith(boom);
    } finally {
      await running.close();
    }
  });

  it("defaults to console.error when onError is not provided", async () => {
    const consoleError = vi.spyOn(console, "error").mockImplementation(() => {});
    const running = await serveDevRegistry({ port: 0 });
    try {
      const boom = new Error("default onError boom");
      running.registry.handler = () => Promise.reject(boom);
      const response = await fetch(`${running.url}/blobs`, {
        method: "POST",
        headers: {
          "content-type": "application/vnd.ipld.raw",
          "if-none-match": "*",
          "x-delete-after": futureIso(),
        },
        body: new Uint8Array([1, 2, 3]),
      });
      expect(response.status).toBe(500);
      expect(consoleError).toHaveBeenCalled();
      const callArgs = consoleError.mock.calls[0] ?? [];
      expect(callArgs).toContain(boom);
    } finally {
      consoleError.mockRestore();
      await running.close();
    }
  });
});
