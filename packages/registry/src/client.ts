/**
 * Registry client — browser + node, fetch-based. MUST NOT import anything
 * node-only (the dev server lives in ./dev-server.ts, node-only).
 *
 * Trustless posture (specs/sharing-viewer-and-registry.md §6):
 * - `putBlob` recomputes the CID locally and asserts the server agrees —
 *   the server's CID is never trusted.
 * - `fetchBlob` re-verifies the CID of every received byte — the gateway is
 *   untrusted; wrong bytes throw `CidMismatchError`.
 * Fail closed everywhere: non-2xx, wrong content-type, oversize — all throw.
 */
import { computeCid, verifyCid } from "@tinycloud/share-envelope";
import { CID } from "multiformats/cid";
import * as raw from "multiformats/codecs/raw";
import { sha256 } from "multiformats/hashes/sha2";

import {
  BlobTooLargeError,
  CidMismatchError,
  RegistryHttpError,
} from "./errors.js";

/** Trustless-gateway raw-block content type (kubo: `/ipfs/<cid>?format=raw`). */
export const RAW_BLOCK_CONTENT_TYPE = "application/vnd.ipld.raw";

/**
 * Default size cap. Envelopes are 1-2 KB (blueprint §2.1); 64 KiB leaves
 * generous headroom while keeping the registry useless as a file host.
 */
export const DEFAULT_MAX_BLOB_BYTES = 64 * 1024;

/**
 * Upload header carrying the retention expiry as a strict ISO-8601
 * timestamp. Required on every upload — the server never defaults to
 * permanent retention (spec §6 step 5: expiry is privacy hygiene, and
 * defaulting to permanent breaks that model).
 */
export const DELETE_AFTER_HEADER = "x-delete-after";

/**
 * Create-only wire contract (spec §6 step 2): every upload must assert
 * `If-None-Match: *`; the dev server rejects uploads missing it.
 */
export const IF_NONE_MATCH_HEADER = "if-none-match";
export const IF_NONE_MATCH_CREATE_ONLY = "*";

export interface RegistryClientOptions {
  /** Size cap in bytes for uploads and downloads. Default {@link DEFAULT_MAX_BLOB_BYTES}. */
  maxBlobBytes?: number;
  /** Fetch implementation override (tests inject an in-process handler here). */
  fetchFn?: typeof globalThis.fetch;
}

function baseUrl(registryBaseUrl: string): string {
  return registryBaseUrl.replace(/\/+$/, "");
}

function mediaType(contentType: string | null): string {
  if (contentType === null) return "";
  const first = contentType.split(";")[0];
  return (first ?? "").trim().toLowerCase();
}

/**
 * Fail-closed cap validation: NaN/Infinity/0/negative/fractional values
 * would make every `> maxBytes` comparison false, silently disabling the
 * cap instead of enforcing it — and huge finite values beyond
 * `Number.MAX_SAFE_INTEGER` (e.g. `Number.MAX_VALUE`) overflow retention/size
 * arithmetic to Infinity, disabling clamps the same way. Require a safe
 * positive integer; reject everything else at construction time.
 */
export function assertPositiveInt(value: number, label: string): number {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new TypeError(
      `${label} must be a positive safe integer, got ${value}`,
    );
  }
  return value;
}

/**
 * Reject anything that isn't a canonical CIDv1/raw/sha2-256 base32 CID
 * before any network call — a malformed CID, a CIDv0 (`Qm…`), or a
 * non-canonical (e.g. uppercase) string form is never worth a round trip,
 * since `verifyCid` would reject it after the fact anyway.
 */
function assertCanonicalCid(cidString: string): void {
  let cid: CID;
  try {
    cid = CID.parse(cidString);
  } catch {
    throw new TypeError(
      `not a canonical CIDv1 raw sha2-256 base32 CID: ${cidString}`,
    );
  }
  if (
    cid.version !== 1 ||
    cid.code !== raw.code ||
    cid.multihash.code !== sha256.code ||
    cid.toString() !== cidString
  ) {
    throw new TypeError(
      `not a canonical CIDv1 raw sha2-256 base32 CID: ${cidString}`,
    );
  }
}

function normalizeDeleteAfter(deleteAfter: Date | string): string {
  if (deleteAfter instanceof Date) {
    if (!Number.isFinite(deleteAfter.getTime())) {
      throw new TypeError("putBlob: deleteAfter is an invalid Date");
    }
    return deleteAfter.toISOString();
  }
  if (typeof deleteAfter === "string" && deleteAfter.length > 0) {
    return deleteAfter;
  }
  // Fail closed: putBlob's deleteAfter parameter is required — a caller
  // ignoring the type system (plain JS, `any`, etc.) must not be able to
  // silently fall through to server-default (permanent) retention.
  throw new TypeError(
    "putBlob: deleteAfter is required (Date or ISO-8601 string)",
  );
}

/**
 * A minimal `Body`-mixin surface shared by `Request` and `Response`, so this
 * helper works on either side of the wire.
 */
interface BoundedBodySource {
  headers: Headers;
  body: ReadableStream<Uint8Array> | null;
  arrayBuffer(): Promise<ArrayBuffer>;
}

/**
 * Read a `Request`/`Response` body up to `maxBytes` without ever buffering
 * more than that into memory. If `Content-Length` is present and already
 * exceeds the cap, throws immediately — no read at all. Otherwise streams
 * via the WHATWG reader and cancels the stream the moment the running total
 * would exceed the cap (a hostile peer cannot omit/lie about
 * `Content-Length` to force an unbounded buffer). Browser-safe: only the
 * standard `Headers`/`ReadableStream` APIs, no node imports.
 */
export async function readBodyBounded(
  source: BoundedBodySource,
  maxBytes: number,
): Promise<Uint8Array> {
  const contentLengthHeader = source.headers.get("content-length");
  if (contentLengthHeader !== null) {
    const contentLength = Number(contentLengthHeader);
    if (Number.isFinite(contentLength) && contentLength > maxBytes) {
      throw new BlobTooLargeError(contentLength, maxBytes);
    }
  }
  if (source.body === null) {
    const bytes = new Uint8Array(await source.arrayBuffer());
    if (bytes.byteLength > maxBytes) {
      throw new BlobTooLargeError(bytes.byteLength, maxBytes);
    }
    return bytes;
  }
  const reader = source.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (value === undefined) continue;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel();
      throw new BlobTooLargeError(total, maxBytes);
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return bytes;
}

/**
 * Upload a sealed blob to the registry's create-only upload endpoint
 * (`POST /blobs`). The returned CID is the locally computed one; the server's
 * claimed CID is only ever used as a cross-check.
 *
 * `deleteAfter` is required (fail closed): the server never defaults
 * retention to permanent, so callers cannot omit an expiry either. The
 * server may clamp it to its retention horizon; the effective value it
 * applied is returned in `deleteAfter`.
 */
export async function putBlob(
  registryBaseUrl: string,
  blob: Uint8Array,
  deleteAfter: Date | string,
  options: RegistryClientOptions = {},
): Promise<{ cid: string; deleteAfter: string }> {
  const maxBlobBytes = assertPositiveInt(
    options.maxBlobBytes ?? DEFAULT_MAX_BLOB_BYTES,
    "maxBlobBytes",
  );
  if (blob.byteLength > maxBlobBytes) {
    throw new BlobTooLargeError(blob.byteLength, maxBlobBytes);
  }
  const deleteAfterValue = normalizeDeleteAfter(deleteAfter);
  const expectedCid = await computeCid(blob);
  const fetchFn = options.fetchFn ?? globalThis.fetch;
  const url = `${baseUrl(registryBaseUrl)}/blobs`;
  const response = await fetchFn(url, {
    method: "POST",
    headers: {
      "content-type": RAW_BLOCK_CONTENT_TYPE,
      [IF_NONE_MATCH_HEADER]: IF_NONE_MATCH_CREATE_ONLY,
      [DELETE_AFTER_HEADER]: deleteAfterValue,
    },
    body: blob as BodyInit,
  });
  if (!response.ok) {
    throw new RegistryHttpError("putBlob failed", response.status, url);
  }
  let body: unknown;
  try {
    body = await response.json();
  } catch {
    throw new RegistryHttpError(
      "putBlob: response body is not JSON",
      response.status,
      url,
    );
  }
  const record =
    typeof body === "object" && body !== null
      ? (body as Record<string, unknown>)
      : {};
  const serverCid = typeof record.cid === "string" ? record.cid : undefined;
  if (serverCid === undefined) {
    throw new RegistryHttpError(
      "putBlob: response body has no string `cid`",
      response.status,
      url,
    );
  }
  // Never trust the server's CID — assert it matches the local computation.
  if (serverCid !== expectedCid) {
    throw new CidMismatchError(expectedCid, serverCid);
  }
  const effectiveDeleteAfter =
    typeof record.deleteAfter === "string" ? record.deleteAfter : undefined;
  if (effectiveDeleteAfter === undefined) {
    throw new RegistryHttpError(
      "putBlob: response body has no string `deleteAfter`",
      response.status,
      url,
    );
  }
  return { cid: expectedCid, deleteAfter: effectiveDeleteAfter };
}

/**
 * Fetch a blob by CID via the trustless-gateway path
 * (`GET /ipfs/<cid>?format=raw`, `Accept: application/vnd.ipld.raw`) and
 * verify the bytes against the CID before returning them.
 */
export async function fetchBlob(
  registryBaseUrl: string,
  cid: string,
  options: RegistryClientOptions = {},
): Promise<Uint8Array> {
  const maxBlobBytes = assertPositiveInt(
    options.maxBlobBytes ?? DEFAULT_MAX_BLOB_BYTES,
    "maxBlobBytes",
  );
  assertCanonicalCid(cid);
  const fetchFn = options.fetchFn ?? globalThis.fetch;
  const url = `${baseUrl(registryBaseUrl)}/ipfs/${cid}?format=raw`;
  const response = await fetchFn(url, {
    headers: { accept: RAW_BLOCK_CONTENT_TYPE },
  });
  if (!response.ok) {
    throw new RegistryHttpError("fetchBlob failed", response.status, url);
  }
  const contentType = mediaType(response.headers.get("content-type"));
  if (contentType !== RAW_BLOCK_CONTENT_TYPE) {
    throw new RegistryHttpError(
      `fetchBlob: unexpected content-type "${contentType}", want ${RAW_BLOCK_CONTENT_TYPE}`,
      response.status,
      url,
    );
  }
  // Bounded read: a hostile gateway cannot OOM the caller by declaring (or
  // omitting) a large body — see readBodyBounded.
  const bytes = await readBodyBounded(response, maxBlobBytes);
  // The gateway is untrusted: the URL's CID is the only source of truth.
  if (!(await verifyCid(bytes, cid))) {
    throw new CidMismatchError(cid, await computeCid(bytes));
  }
  return bytes;
}
