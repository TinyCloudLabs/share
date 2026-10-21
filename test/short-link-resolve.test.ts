import { readFileSync } from "node:fs";
import { afterEach, describe, expect, it, vi } from "vitest";
import { fromBase64Url } from "@tinycloud/share-envelope";
import { ShortLinkError } from "../src/short-links/errors.js";
import { inlineHrefForShortLink, MAX_SEALED_BYTES } from "../src/short-links/resolve.js";

interface Vector {
  readonly inline: string;
  readonly id: string;
  readonly ciphertextB64Url: string;
  readonly cid: string;
  readonly k: string;
  readonly short: string;
}

const raw = JSON.parse(readFileSync("test/fixtures/shortlink-vectors.json", "utf8")) as Record<string, Vector>;
const first = raw["0"] as Vector;
const ORIGIN = "https://share.tinycloud.xyz";
const OCTET = { "content-type": "application/octet-stream" };

interface Call {
  readonly url: string;
  readonly init: RequestInit | undefined;
}

/** A fetch stand-in that records each call and answers with the given response factory. */
function fetchReturning(respond: (init: RequestInit | undefined) => Response | Promise<Response>): { readonly fn: typeof fetch; readonly calls: Call[] } {
  const calls: Call[] = [];
  const fn: typeof fetch = async (input, init) => {
    calls.push({ url: String(input), init });
    return respond(init);
  };
  return { fn, calls };
}

function sealedResponse(headers: Record<string, string> = OCTET): Response {
  return new Response(Uint8Array.from(fromBase64Url(first.ciphertextB64Url)), { status: 200, headers });
}

afterEach(() => {
  vi.useRealTimers();
});

describe("inlineHrefForShortLink: success", () => {
  it("returns the inline link the shared vector records", async () => {
    const { fn } = fetchReturning(() => sealedResponse());
    await expect(inlineHrefForShortLink(first.short, ORIGIN, fn)).resolves.toBe(first.inline);
  });

  it("requests only the lowercase id, with no credentials, no redirects and no cache", async () => {
    const { fn, calls } = fetchReturning(() => sealedResponse());
    await inlineHrefForShortLink(first.short.replace(first.id, first.id.toUpperCase()), ORIGIN, fn);
    expect(calls).toHaveLength(1);
    const call = calls[0] as Call;
    expect(call.url).toBe(`${ORIGIN}/api/share-links/${first.id}`);
    expect(call.init?.credentials).toBe("omit");
    expect(call.init?.redirect).toBe("error");
    expect(call.init?.cache).toBe("no-store");
  });

  it("never sends the content key or the cid in the url, headers or body", async () => {
    const { fn, calls } = fetchReturning(() => sealedResponse());
    await inlineHrefForShortLink(first.short, ORIGIN, fn);
    const call = calls[0] as Call;
    expect(call.url).not.toContain(first.k);
    expect(call.url).not.toContain(first.cid);
    expect(call.url).not.toContain("#");
    expect(call.init?.body).toBeUndefined();
    expect([...new Headers(call.init?.headers).keys()]).toEqual([]);
  });
});

describe("inlineHrefForShortLink: gone", () => {
  it("maps 404 to gone", async () => {
    const { fn } = fetchReturning(() => new Response(null, { status: 404 }));
    const failure = await inlineHrefForShortLink(first.short, ORIGIN, fn).catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(ShortLinkError);
    expect(failure).toMatchObject({ reason: "gone" });
  });
});

describe("inlineHrefForShortLink: unavailable", () => {
  it.each([429, 500, 503, 301])("maps status %i to unavailable", async (status) => {
    const { fn } = fetchReturning(() => new Response(null, { status }));
    await expect(inlineHrefForShortLink(first.short, ORIGIN, fn)).rejects.toMatchObject({ reason: "unavailable" });
  });

  it("maps a refused redirect, which fetch reports as a rejection, to unavailable", async () => {
    const { fn } = fetchReturning(() => Promise.reject(new TypeError("redirect mode is set to error")));
    await expect(inlineHrefForShortLink(first.short, ORIGIN, fn)).rejects.toMatchObject({ reason: "unavailable" });
  });

  it("maps a network failure to unavailable", async () => {
    const { fn } = fetchReturning(() => Promise.reject(new TypeError("network down")));
    await expect(inlineHrefForShortLink(first.short, ORIGIN, fn)).rejects.toMatchObject({ reason: "unavailable" });
  });

  it("maps a request that never answers to unavailable after 15 seconds", async () => {
    vi.useFakeTimers();
    const fn: typeof fetch = (_input, init) => new Promise((_resolve, reject) => {
      init?.signal?.addEventListener("abort", () => reject(new TypeError("aborted")));
    });
    const outcome = inlineHrefForShortLink(first.short, ORIGIN, fn).catch((error: unknown) => error);
    await vi.advanceTimersByTimeAsync(15_000);
    expect(await outcome).toMatchObject({ reason: "unavailable" });
  });

  it.each(["text/plain", "application/json", ""])("refuses content type %j", async (contentType) => {
    const { fn } = fetchReturning(() => sealedResponse({ "content-type": contentType }));
    await expect(inlineHrefForShortLink(first.short, ORIGIN, fn)).rejects.toMatchObject({ reason: "unavailable" });
  });

  it("refuses a declared length above the cap before reading the body", async () => {
    const { fn } = fetchReturning(() => sealedResponse({ ...OCTET, "content-length": String(MAX_SEALED_BYTES + 1) }));
    await expect(inlineHrefForShortLink(first.short, ORIGIN, fn)).rejects.toMatchObject({ reason: "unavailable" });
  });

  it("refuses a body that streams past the cap without a declared length", async () => {
    const { fn } = fetchReturning(() => {
      const body = new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(new Uint8Array(MAX_SEALED_BYTES + 1));
          controller.close();
        },
      });
      return new Response(body, { status: 200, headers: OCTET });
    });
    await expect(inlineHrefForShortLink(first.short, ORIGIN, fn)).rejects.toMatchObject({ reason: "unavailable" });
  });

  it("refuses an empty body", async () => {
    const { fn } = fetchReturning(() => new Response(new Uint8Array(0), { status: 200, headers: OCTET }));
    await expect(inlineHrefForShortLink(first.short, ORIGIN, fn)).rejects.toMatchObject({ reason: "unavailable" });
  });

  it("refuses a JSON body, which does not match the cid", async () => {
    const { fn } = fetchReturning(() => new Response('{"ciphertext":"abc"}', { status: 200, headers: OCTET }));
    await expect(inlineHrefForShortLink(first.short, ORIGIN, fn)).rejects.toMatchObject({ reason: "unavailable" });
  });

  it("refuses bytes whose cid does not match, and returns no inline link", async () => {
    const tampered = Uint8Array.from(fromBase64Url(first.ciphertextB64Url));
    tampered[0] = (tampered[0] ?? 0) ^ 0xff;
    const { fn } = fetchReturning(() => new Response(tampered, { status: 200, headers: OCTET }));
    const result = await inlineHrefForShortLink(first.short, ORIGIN, fn).then(
      (href) => ({ href }),
      (error: unknown) => ({ error }),
    );
    expect(result).toEqual({ error: expect.any(ShortLinkError) });
    expect(result).not.toHaveProperty("href");
    expect(result).toMatchObject({ error: { reason: "unavailable" } });
  });

  it("refuses a malformed short link without calling the server", async () => {
    const { fn, calls } = fetchReturning(() => sealedResponse());
    await expect(inlineHrefForShortLink(`${ORIGIN}/s/short`, ORIGIN, fn)).rejects.toMatchObject({ reason: "unavailable" });
    expect(calls).toHaveLength(0);
  });
});
