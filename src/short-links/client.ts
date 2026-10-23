/**
 * Client for the links API. The API origin comes from configuration, never from a link.
 * Requests never carry the content key, the CID in the link, or any part of a link's fragment.
 * Nothing here logs a body, a signature or a URL.
 */
import { fromBase64Url, toBase64Url } from "@tinycloud/share-envelope";
import type { DeleteRequest, LinkHeader, LinkSignature } from "./record.js";

export const LINK_API_TIMEOUT_MS = 15_000;
/** The `X-Link-Record` header is at most 2 KiB (contract 5.2). */
const MAX_RECORD_HEADER_CHARS = 2_048;
const ID = /^[a-z2-7]{26}$/;

export type LinkApiFailure = "network" | "timeout" | "rate_limited" | "capacity" | "rejected" | "replayed" | "blocked" | "server" | "invalid_response";

export class LinkApiError extends Error {
  readonly reason: LinkApiFailure;
  constructor(reason: LinkApiFailure) {
    super(`links api ${reason}`);
    this.name = "LinkApiError";
    this.reason = reason;
  }
}

export interface LinkApiOptions {
  /** `https://api.tinycloud.xyz` or a self-hosted instance, from configuration. */
  readonly apiOrigin: string;
  readonly fetchFn?: typeof fetch | undefined;
  readonly timeoutMs?: number | undefined;
}

interface Exchange {
  readonly response: Response;
  readonly signal: AbortSignal;
  readonly done: () => void;
  readonly timedOut: () => boolean;
}

async function send(url: string, init: RequestInit, options: LinkApiOptions): Promise<Exchange> {
  const controller = new AbortController();
  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, options.timeoutMs ?? LINK_API_TIMEOUT_MS);
  const done = (): void => clearTimeout(timer);
  try {
    const response = await (options.fetchFn ?? fetch)(url, { ...init, credentials: "omit", redirect: "error", referrerPolicy: "no-referrer", cache: "no-store", signal: controller.signal });
    return { response, signal: controller.signal, done, timedOut: () => timedOut };
  } catch {
    done();
    throw new LinkApiError(timedOut ? "timeout" : "network");
  }
}

function failureFor(status: number): LinkApiFailure {
  if (status === 429) return "rate_limited";
  if (status === 503) return "capacity";
  if (status === 409) return "replayed";
  if (status === 403) return "blocked";
  if (status >= 400 && status < 500) return "rejected";
  return "server";
}

const jsonPost = (body: unknown): RequestInit => ({ method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });

/** Creates a link record. The request body is the record the contract defines and nothing else. */
export async function createLink(
  record: { readonly header: LinkHeader; readonly signature: LinkSignature; readonly body: Uint8Array },
  options: LinkApiOptions,
): Promise<{ readonly id: string; readonly expiresAt: string }> {
  const exchange = await send(`${options.apiOrigin}/v1/links`, jsonPost({ header: record.header, signature: record.signature, body: toBase64Url(record.body) }), options);
  try {
    if (exchange.response.status !== 201) throw new LinkApiError(failureFor(exchange.response.status));
    const created = (await exchange.response.json().catch(() => undefined)) as Record<string, unknown> | undefined;
    if (typeof created !== "object" || created === null || typeof created["id"] !== "string" || !ID.test(created["id"]) || typeof created["expiresAt"] !== "string") {
      throw new LinkApiError("invalid_response");
    }
    return { id: created["id"], expiresAt: created["expiresAt"] };
  } finally {
    exchange.done();
  }
}

/**
 * Deletes a link with an issuer-signed request. `deleted` is a 204; `absent` is the uniform 404
 * (unknown, expired, already deleted, or not this issuer's). Anything else throws.
 */
export async function deleteLink(
  signed: { readonly request: DeleteRequest; readonly signature: LinkSignature },
  options: LinkApiOptions,
): Promise<"deleted" | "absent"> {
  if (!ID.test(signed.request.id)) throw new LinkApiError("rejected");
  const exchange = await send(`${options.apiOrigin}/v1/links/${signed.request.id}/delete`, jsonPost(signed), options);
  try {
    if (exchange.response.status === 204) return "deleted";
    if (exchange.response.status === 404) return "absent";
    throw new LinkApiError(failureFor(exchange.response.status));
  } finally {
    exchange.done();
  }
}

/** What a read returns: the stored header, its signature when there is one, and the sealed body. */
export interface FetchedRecord {
  readonly header: unknown;
  readonly signature?: unknown;
  readonly body: Uint8Array;
}

/**
 * `GET /v1/links/{id}`: no query, no credentials. `undefined` is the uniform 404. The body is read
 * with a running cap; a larger body is refused as unusable.
 */
export async function readLinkRecord(id: string, maxBodyBytes: number, options: LinkApiOptions): Promise<FetchedRecord | undefined> {
  if (!ID.test(id)) throw new LinkApiError("rejected");
  const exchange = await send(`${options.apiOrigin}/v1/links/${id}`, { method: "GET" }, options);
  try {
    const { response } = exchange;
    if (response.status === 404) return undefined;
    if (response.status !== 200) throw new LinkApiError(failureFor(response.status));
    const contentType = (response.headers.get("content-type") ?? "").split(";")[0]?.trim().toLowerCase();
    if (contentType !== "application/octet-stream") throw new LinkApiError("invalid_response");
    const declared = response.headers.get("content-length");
    if (declared !== null && Number(declared) > maxBodyBytes) throw new LinkApiError("invalid_response");
    const meta = response.headers.get("x-link-record");
    if (meta === null || meta.length > MAX_RECORD_HEADER_CHARS) throw new LinkApiError("invalid_response");
    let parsed: unknown;
    try {
      parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(fromBase64Url(meta)));
    } catch {
      throw new LinkApiError("invalid_response");
    }
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) throw new LinkApiError("invalid_response");
    const fields = Object.keys(parsed).sort().join(",");
    if (fields !== "header" && fields !== "header,signature") throw new LinkApiError("invalid_response");
    const body = await readCapped(response, maxBodyBytes, exchange);
    const { header, signature } = parsed as { header: unknown; signature?: unknown };
    return signature === undefined ? { header, body } : { header, signature, body };
  } finally {
    exchange.done();
  }
}

async function readCapped(response: Response, max: number, exchange: Exchange): Promise<Uint8Array> {
  if (response.body === null) return new Uint8Array(0);
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  const onAbort = (): void => { void reader.cancel(); };
  exchange.signal.addEventListener("abort", onAbort, { once: true });
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > max) {
        await reader.cancel();
        throw new LinkApiError("invalid_response");
      }
      chunks.push(value);
    }
  } catch (error) {
    if (error instanceof LinkApiError) throw error;
    throw new LinkApiError(exchange.timedOut() ? "timeout" : "network");
  } finally {
    exchange.signal.removeEventListener("abort", onAbort);
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return out;
}
