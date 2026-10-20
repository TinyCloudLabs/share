import { describe, expect, it, vi } from "vitest";

import { keys } from "../src/courier/model.ts";
import { MAX_CONCURRENT_READS, StoreError, createKvStore, type CourierKv } from "../src/courier/store.ts";

const REQ = "01J9ZC4K7T3QZ5W6M8R2N1B030";
const file = { requestId: REQ, requestHash: "a".repeat(64), decision: "approved", note: "", decidedAt: "2026-10-20T12:00:00.000Z" } as const;
const ok = <T,>(data: T) => ({ ok: true as const, data });
const headers = { get: () => null };

type Put = CourierKv["put"];
type Get = CourierKv["get"];
type List = CourierKv["list"];
const kvWith = (parts: { put?: Put; get?: Get; list?: List }): CourierKv => ({
  put: parts.put ?? (vi.fn() as unknown as Put),
  get: parts.get ?? (vi.fn() as unknown as Get),
  list: parts.list ?? (vi.fn() as unknown as List),
});

describe("approvals are create-only", () => {
  it("writes the key under me/approvals/ with If-None-Match: * and full-path keys", async () => {
    const put = vi.fn(async (..._args: unknown[]) => ok({ data: undefined, headers }));
    const store = createKvStore(kvWith({ put: put as unknown as Put }));
    await expect(store.createApproval(file)).resolves.toBe("created");
    expect(put).toHaveBeenCalledWith(keys.approval(REQ), JSON.stringify(file), expect.objectContaining({ ifNoneMatch: "*", prefix: "", contentType: "application/json" }));
    expect(String(put.mock.calls[0]?.[0])).toBe(`xyz.tinycloud.courier/me/approvals/${REQ}.json`);
  });
  it("reports 412 as already decided and does not retry or overwrite", async () => {
    const put = vi.fn(async () => ({ ok: false as const, error: { code: "KV_PRECONDITION_FAILED", message: "412", service: "kv" } }));
    const store = createKvStore(kvWith({ put: put as unknown as Put }));
    await expect(store.createApproval(file)).resolves.toBe("exists");
    expect(put).toHaveBeenCalledTimes(1);
  });
  it("maps a refused write to a denied failure without echoing the node's message", async () => {
    const put = vi.fn(async () => ({ ok: false as const, error: { code: "AUTH", message: "secret detail 0xabc", service: "kv", meta: { status: 401 } } }));
    const store = createKvStore(kvWith({ put: put as unknown as Put }));
    const failure = await store.createApproval(file).catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(StoreError);
    expect((failure as StoreError).code).toBe("denied");
    expect((failure as StoreError).message).not.toContain("secret");
  });
});

describe("orders are compare-and-swap", () => {
  it("uses If-Match with the etag read, or create-only when there was no file", async () => {
    const put = vi.fn(async (..._args: unknown[]) => ok({ data: undefined, headers }));
    const store = createKvStore(kvWith({ put: put as unknown as Put }));
    await store.writeOrders("hunter", "# x", "etag-9");
    await store.writeOrders("hunter", "# x", undefined);
    expect(put.mock.calls[0]).toEqual(["xyz.tinycloud.courier/me/orders/hunter.md", "# x", expect.objectContaining({ ifMatch: "etag-9" })]);
    expect(put.mock.calls[1]?.[2]).toEqual(expect.objectContaining({ ifNoneMatch: "*" }));
  });
  it("reports a lost race as changed", async () => {
    const put = vi.fn(async () => ({ ok: false as const, error: { code: "KV_PRECONDITION_FAILED", message: "", service: "kv" } }));
    await expect(createKvStore(kvWith({ put: put as unknown as Put })).writeOrders("hunter", "x", "e")).rejects.toMatchObject({ code: "changed" });
  });
  it("refuses an orders file over the size cap before any request", async () => {
    const put = vi.fn();
    await expect(createKvStore(kvWith({ put: put as unknown as Put })).writeOrders("hunter", "x".repeat(70 * 1024), "e")).rejects.toMatchObject({ code: "too-large" });
    expect(put).not.toHaveBeenCalled();
  });
});

describe("reads are bounded", () => {
  it("gives up on a call the node never answers", async () => {
    vi.useFakeTimers();
    try {
      const get = vi.fn(() => new Promise<never>(() => undefined));
      const store = createKvStore(kvWith({ get: get as unknown as Get }), { callTimeoutMs: 20 });
      const outcome = store.readJson("xyz.tinycloud.courier/me/requests/x.json").catch((error: unknown) => error);
      await vi.advanceTimersByTimeAsync(25);
      expect(await outcome).toMatchObject({ code: "timeout" });
    } finally {
      vi.useRealTimers();
    }
  });
  it("asks the node to stop at a response-size cap", async () => {
    const get = vi.fn(async (..._args: unknown[]) => ok({ data: "{}", headers }));
    await createKvStore(kvWith({ get: get as unknown as Get })).readJson("k");
    expect(get.mock.calls[0]?.[1]).toEqual(expect.objectContaining({ maxResponseBytes: expect.any(Number), prefix: "" }));
  });
  it("treats a missing key as absent and a too-large answer as a failure", async () => {
    const missing = vi.fn(async () => ({ ok: false as const, error: { code: "KV_NOT_FOUND", message: "", service: "kv" } }));
    await expect(createKvStore(kvWith({ get: missing as unknown as Get })).readJson("k")).resolves.toBeUndefined();
    const big = vi.fn(async () => ({ ok: false as const, error: { code: "KV_RESPONSE_TOO_LARGE", message: "", service: "kv" } }));
    await expect(createKvStore(kvWith({ get: big as unknown as Get })).readJson("k")).rejects.toMatchObject({ code: "too-large" });
  });
  it("runs at most a few reads at once", async () => {
    let running = 0; let peak = 0;
    const gates: (() => void)[] = [];
    const get = vi.fn(() => {
      running += 1; peak = Math.max(peak, running);
      return new Promise((resolve) => { gates.push(() => { running -= 1; resolve(ok({ data: "{}", headers })); }); });
    });
    const store = createKvStore(kvWith({ get: get as unknown as Get }));
    const all = Promise.all(Array.from({ length: 30 }, (_, index) => store.readJson(`k${index}`)));
    const release = async (): Promise<void> => {
      while (get.mock.calls.length < 30 || gates.length > 0) {
        await vi.waitFor(() => expect(gates.length).toBeGreaterThan(0));
        for (const open of gates.splice(0)) open();
      }
    };
    await Promise.all([all, release()]);
    expect(peak).toBeLessThanOrEqual(MAX_CONCURRENT_READS);
    expect(get).toHaveBeenCalledTimes(30);
  });
  it("stops walking a listing whose cursor does not advance (TC-719) and says it is partial", async () => {
    const list = vi.fn(async () => ok({ keys: ["xyz.tinycloud.courier/a"], truncated: true, nextCursor: "same" }));
    const result = await createKvStore(kvWith({ list: list as unknown as List })).list();
    expect(list).toHaveBeenCalledTimes(2);
    expect(result).toEqual({ keys: ["xyz.tinycloud.courier/a"], truncated: true });
  });
  it("reads a missing space as no-space, not as an empty mailbox", async () => {
    const list = vi.fn(async () => ({ ok: false as const, error: { code: "KV_NOT_FOUND", message: "Space not found", service: "kv", meta: { status: 404 } } }));
    await expect(createKvStore(kvWith({ list: list as unknown as List })).list()).rejects.toMatchObject({ code: "no-space" });
  });
});
