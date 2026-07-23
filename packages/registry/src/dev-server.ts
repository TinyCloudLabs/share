/**
 * Local dev registry server — NODE-ONLY module (imports node:http).
 *
 * Simulates the production single-uploader kubo posture
 * (specs/sharing-viewer-and-registry.md §6.2) closely enough that a real kubo
 * behind the same paths is a drop-in swap:
 *
 * - `POST /blobs` — create-only upload. Atomic ingestion per §6: compute the
 *   canonical raw CID → (assert; identity here because the dev server IS the
 *   CID computer, whereas prod asserts kubo's returned CID) → store bytes →
 *   persist the retention record. All of that lands in one Map entry before
 *   `{ cid }` is returned. Existing CID succeeds only on byte-identical
 *   content (idempotent), otherwise 409.
 * - `GET /ipfs/<cid>?format=raw` — trustless-gateway response shape:
 *   `Content-Type: application/vnd.ipld.raw`, `Cache-Control` bounded by any
 *   `deleteAfter`. 406 without `?format=raw` or a raw `Accept` header.
 * - `GET /blobs/<cid>` — convenience alias, same response shape.
 * - NoFetch posture: serves ONLY the local store; never touches any network.
 * - `sweepExpired()` dev-simulates the `ipfs pin rm` + `repo gc` expiry cron.
 *
 * Library-first: `createDevRegistry()` returns a web-standard
 * `(Request) => Promise<Response>` handler so tests drive it in-process
 * without binding a port; `serveDevRegistry()` wraps it in node:http.
 */
import { createServer, type Server } from "node:http";

import { computeCid } from "@tinycloud/share-envelope";

import {
  DEFAULT_MAX_BLOB_BYTES,
  DELETE_AFTER_HEADER,
  IF_NONE_MATCH_CREATE_ONLY,
  IF_NONE_MATCH_HEADER,
  RAW_BLOCK_CONTENT_TYPE,
  assertPositiveInt,
  readBodyBounded,
} from "./client.js";
import { BlobTooLargeError } from "./errors.js";

export { DELETE_AFTER_HEADER };

/**
 * Retention record persisted atomically with the bytes at upload time
 * (dev stand-in for §6's "persist retention record (CID, deleteAfter,
 * uploader)"; there is no uploader identity in the dev server).
 *
 * `deleteAfter` is required: uploads without a retention expiry are
 * rejected (never default-permanent — see `handleUpload`).
 */
export interface RetentionRecord {
  readonly bytes: Uint8Array;
  /** Upload time, epoch milliseconds. */
  readonly uploadedAt: number;
  /** Expiry, epoch milliseconds. */
  readonly deleteAfter: number;
}

/** Default retention horizon: 30 days. `deleteAfter` values beyond this are clamped. */
export const DEFAULT_MAX_RETENTION_SECONDS = 30 * 24 * 60 * 60;

export interface DevRegistryOptions {
  /** Upload size cap in bytes. Default {@link DEFAULT_MAX_BLOB_BYTES}. */
  maxBlobBytes?: number;
  /** Retention horizon in seconds. Default {@link DEFAULT_MAX_RETENTION_SECONDS}. */
  maxRetentionSeconds?: number;
}

export interface DevRegistry {
  /** Web-standard handler; drive it directly in tests (no port needed). */
  handler: (request: Request) => Promise<Response>;
  /** The in-memory store, keyed by CID. Exposed so tests can inject tampering. */
  store: Map<string, RetentionRecord>;
  /** Drop expired entries; returns how many were dropped. `now` defaults to Date.now(). */
  sweepExpired: (now?: number) => number;
  maxBlobBytes: number;
}

/** Kubo's immutable-response max-age (~48 weeks); the dev server mirrors it. */
const DEFAULT_MAX_AGE_SECONDS = 29030400;

/**
 * Strict ISO-8601 timestamp: `YYYY-MM-DDTHH:mm:ss(.sss)?(Z|±hh:mm)`. Rejects
 * anything `Date.parse` alone would accept loosely (e.g. `"January 1, 2099"`).
 */
const STRICT_ISO_8601_RE =
  /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,3})?(?:Z|[+-]\d{2}:\d{2})$/;

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.byteLength !== b.byteLength) return false;
  for (let i = 0; i < a.byteLength; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

function isExpired(record: RetentionRecord, now: number): boolean {
  return record.deleteAfter <= now;
}

/**
 * Minimal `Accept` matching for the raw-block media type: parses `q` params
 * just enough to honor `q=0` ("not acceptable" per RFC 9110 §12.5.1) — an
 * `Accept: application/vnd.ipld.raw;q=0` must NOT match even though the
 * media type is present.
 */
function acceptsRawBlock(accept: string | null): boolean {
  if (accept === null || accept.length === 0) return false;
  for (const entry of accept.split(",")) {
    const parts = entry.split(";").map((part) => part.trim());
    const mediaType = (parts[0] ?? "").toLowerCase();
    if (mediaType !== RAW_BLOCK_CONTENT_TYPE) continue;
    let q = 1;
    for (const param of parts.slice(1)) {
      const [key, value] = param.split("=").map((s) => s.trim());
      // RFC 9110 §12.4.2: the `q` parameter name is case-insensitive and its
      // value must be a number in [0, 1]. Fail closed: a missing, malformed,
      // or out-of-range q value means "not acceptable" (q=0), never "assume
      // acceptable".
      if (key !== undefined && key.toLowerCase() === "q") {
        const parsed = value === undefined ? Number.NaN : Number(value);
        q = Number.isFinite(parsed) && parsed >= 0 && parsed <= 1 ? parsed : 0;
      }
    }
    if (q > 0) return true;
  }
  return false;
}

type DeleteAfterResult =
  | { ok: true; value: number }
  | { ok: false; error: string };

/**
 * Validate the `x-delete-after` header: strict ISO-8601 format, a finite
 * parse, and not already in the past. Values beyond `maxRetentionSeconds`
 * from now are clamped to that horizon (never rejected) so the effective
 * value can be reported back to the caller.
 */
function parseDeleteAfter(
  header: string,
  now: number,
  maxRetentionSeconds: number,
): DeleteAfterResult {
  const match = STRICT_ISO_8601_RE.exec(header);
  if (match === null) {
    return {
      ok: false,
      error: `invalid ${DELETE_AFTER_HEADER}: not a strict ISO-8601 timestamp`,
    };
  }
  // Date.parse silently normalizes impossible calendar dates (e.g.
  // 2099-02-29 becomes March 1), which would accept an expiry the caller
  // never wrote. Reject unless the date/time components round-trip through
  // the calendar exactly.
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const hours = Number(match[4]);
  const minutes = Number(match[5]);
  const seconds = Number(match[6]);
  const roundTrip = new Date(
    Date.UTC(year, month - 1, day, hours, minutes, seconds),
  );
  if (
    roundTrip.getUTCFullYear() !== year ||
    roundTrip.getUTCMonth() !== month - 1 ||
    roundTrip.getUTCDate() !== day ||
    roundTrip.getUTCHours() !== hours ||
    roundTrip.getUTCMinutes() !== minutes ||
    roundTrip.getUTCSeconds() !== seconds
  ) {
    return {
      ok: false,
      error: `invalid ${DELETE_AFTER_HEADER}: not a real calendar date`,
    };
  }
  const parsed = Date.parse(header);
  if (!Number.isFinite(parsed)) {
    return {
      ok: false,
      error: `invalid ${DELETE_AFTER_HEADER}: not a valid timestamp`,
    };
  }
  if (parsed <= now) {
    return { ok: false, error: `${DELETE_AFTER_HEADER} is in the past` };
  }
  const horizon = now + maxRetentionSeconds * 1000;
  return { ok: true, value: Math.min(parsed, horizon) };
}

export function createDevRegistry(
  options: DevRegistryOptions = {},
): DevRegistry {
  const maxBlobBytes = assertPositiveInt(
    options.maxBlobBytes ?? DEFAULT_MAX_BLOB_BYTES,
    "maxBlobBytes",
  );
  const maxRetentionSeconds = assertPositiveInt(
    options.maxRetentionSeconds ?? DEFAULT_MAX_RETENTION_SECONDS,
    "maxRetentionSeconds",
  );
  const store = new Map<string, RetentionRecord>();

  function sweepExpired(now: number = Date.now()): number {
    let dropped = 0;
    for (const [cid, record] of store) {
      if (isExpired(record, now)) {
        store.delete(cid);
        dropped++;
      }
    }
    return dropped;
  }

  async function handleUpload(request: Request): Promise<Response> {
    const now = Date.now();

    // Create-only wire contract (spec §6 step 2): reject uploads missing
    // the precondition header before doing any other work.
    if (request.headers.get(IF_NONE_MATCH_HEADER) !== IF_NONE_MATCH_CREATE_ONLY) {
      return json(428, {
        error: `${IF_NONE_MATCH_HEADER}: ${IF_NONE_MATCH_CREATE_ONLY} header is required for uploads`,
      });
    }

    // Required (never default-permanent): retention is the expiring-share
    // privacy model, so a missing header is rejected, not defaulted.
    const deleteAfterHeader = request.headers.get(DELETE_AFTER_HEADER);
    if (deleteAfterHeader === null) {
      return json(400, { error: `${DELETE_AFTER_HEADER} is required` });
    }
    const deleteAfterResult = parseDeleteAfter(
      deleteAfterHeader,
      now,
      maxRetentionSeconds,
    );
    if (!deleteAfterResult.ok) {
      return json(400, { error: deleteAfterResult.error });
    }
    const deleteAfter = deleteAfterResult.value;

    let bytes: Uint8Array;
    try {
      // Bounded read (never buffer an unbounded body): check Content-Length
      // first, otherwise stream and abort past the cap — see readBodyBounded.
      bytes = await readBodyBounded(request, maxBlobBytes);
    } catch (err) {
      if (err instanceof BlobTooLargeError) {
        return json(413, {
          error: `blob is ${err.byteLength} bytes, cap is ${maxBlobBytes}`,
        });
      }
      throw err;
    }
    if (bytes.byteLength === 0) {
      return json(400, { error: "empty body" });
    }

    // Atomic ingestion (§6): compute → assert → store → retention record.
    // The dev server computes the canonical CID itself, so the prod-side
    // "assert kubo's returned CID == precomputed CID" step is an identity here.
    const cid = await computeCid(bytes);
    // Expired-but-unswept records are treated as ABSENT (fail safe): their
    // retention has already lapsed, so nothing about them — bytes or expiry —
    // may influence this upload. Delete the dead record first so the upload
    // below is a clean create (201) whose stored retention is exactly the
    // newly-requested (validated, clamped) value; the old record's
    // deleteAfter is never reconciled against and never silently extended.
    const stale = store.get(cid);
    if (stale !== undefined && isExpired(stale, now)) {
      store.delete(cid);
    }
    const existing = store.get(cid);
    if (existing !== undefined) {
      // Create-only: an existing CID may succeed only on byte-identical
      // content. With sha2-256 content addressing, different bytes under the
      // same CID cannot occur honestly — this branch is a defensive check
      // against store tampering/corruption, and it fails closed.
      if (!bytesEqual(existing.bytes, bytes)) {
        return json(409, { error: "cid exists with different bytes" });
      }
      // Idempotent re-upload with a possibly different retention: reconcile
      // deterministically — the earliest deleteAfter wins — and persist the
      // reconciled record before responding, so GET's Cache-Control (which
      // reads straight from the store) reflects it too.
      const reconciled = Math.min(existing.deleteAfter, deleteAfter);
      if (reconciled !== existing.deleteAfter) {
        store.set(cid, { ...existing, deleteAfter: reconciled });
      }
      return json(200, {
        cid,
        deleteAfter: new Date(reconciled).toISOString(),
      });
    }
    const record: RetentionRecord = { bytes, uploadedAt: now, deleteAfter };
    store.set(cid, record);
    return json(201, { cid, deleteAfter: new Date(deleteAfter).toISOString() });
  }

  function handleGetBlob(
    cid: string,
    request: Request,
    url: URL,
    requireRawFormat: boolean,
  ): Response {
    if (requireRawFormat) {
      const format = url.searchParams.get("format");
      // `?format=` takes precedence over Accept (trustless-gateway spec):
      // an explicit non-raw format is a hard 406 even if Accept would
      // otherwise be satisfied; `format=raw` is always accepted regardless
      // of what Accept says.
      if (format !== null) {
        if (format !== "raw") {
          return new Response(
            "trustless gateway: only ?format=raw / Accept: application/vnd.ipld.raw is supported",
            { status: 406 },
          );
        }
      } else if (!acceptsRawBlock(request.headers.get("accept"))) {
        return new Response(
          "trustless gateway: only ?format=raw / Accept: application/vnd.ipld.raw is supported",
          { status: 406 },
        );
      }
    }
    const now = Date.now();
    const record = store.get(cid);
    if (record === undefined || isExpired(record, now)) {
      if (record !== undefined) store.delete(cid);
      return new Response("not found", { status: 404 });
    }
    // Cache lifetime is bounded by the retention record so no edge cache can
    // outlive deletion by more than the remaining retention window.
    const maxAge = Math.min(
      DEFAULT_MAX_AGE_SECONDS,
      Math.max(0, Math.floor((record.deleteAfter - now) / 1000)),
    );
    return new Response(record.bytes as BodyInit, {
      status: 200,
      headers: {
        "content-type": RAW_BLOCK_CONTENT_TYPE,
        "cache-control": `public, max-age=${maxAge}, immutable`,
        "x-content-type-options": "nosniff",
      },
    });
  }

  async function handler(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;

    if (
      (request.method === "POST" || request.method === "PUT") &&
      path === "/blobs"
    ) {
      return handleUpload(request);
    }
    if (request.method === "GET") {
      const ipfsMatch = /^\/ipfs\/([^/]+)$/.exec(path);
      if (ipfsMatch?.[1] !== undefined) {
        return handleGetBlob(ipfsMatch[1], request, url, true);
      }
      const blobMatch = /^\/blobs\/([^/]+)$/.exec(path);
      if (blobMatch?.[1] !== undefined) {
        return handleGetBlob(blobMatch[1], request, url, false);
      }
    }
    return new Response("not found", { status: 404 });
  }

  return { handler, store, sweepExpired, maxBlobBytes };
}

export interface ServeDevRegistryOptions extends DevRegistryOptions {
  /** Port to listen on; 0 (default) picks a free port. */
  port?: number;
  /** Host to bind; default 127.0.0.1 (local dev only). */
  host?: string;
  /** Expiry-sweep interval in ms; default 60s. The timer is unref'd. */
  sweepIntervalMs?: number;
  /**
   * Called with the underlying cause whenever an internal error is turned
   * into a generic 500 response. Default: `console.error`. The response
   * body sent to the caller stays a generic 500 either way (fail closed);
   * this only makes the failure observable to the operator.
   */
  onError?: (err: unknown) => void;
}

export interface DevRegistryServer {
  registry: DevRegistry;
  server: Server;
  /** The bound port (resolved after listen). */
  port: number;
  url: string;
  close: () => Promise<void>;
}

/**
 * Bind the dev registry to a real node:http server. The CLI uses this; tests
 * mostly drive `createDevRegistry().handler` directly instead.
 */
export async function serveDevRegistry(
  options: ServeDevRegistryOptions = {},
): Promise<DevRegistryServer> {
  const registry = createDevRegistry(options);
  const host = options.host ?? "127.0.0.1";
  const onError =
    options.onError ??
    ((err: unknown) => {
      console.error("share-registry dev server: internal error", err);
    });

  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    let byteLength = 0;
    let aborted = false;
    req.on("data", (chunk: Buffer) => {
      byteLength += chunk.byteLength;
      // Early cutoff so an oversized upload cannot balloon dev-server memory;
      // read slightly past the cap so the handler still answers 413.
      if (byteLength > registry.maxBlobBytes + 1) {
        aborted = true;
        res.writeHead(413, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: "blob exceeds cap" }));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => {
      if (aborted) return;
      // The entire per-request body — Request construction, handler
      // invocation, response conversion — runs inside one async function so
      // that ANY throw, synchronous or asynchronous, lands in the catch
      // below (onError + generic 500). A bare sync throw from
      // `new Request(...)` or `registry.handler(...)` must never escape.
      void (async () => {
        const body = Buffer.concat(chunks);
        const url = new URL(
          req.url ?? "/",
          `http://${req.headers.host ?? `${host}:0`}`,
        );
        const init: RequestInit & { duplex?: "half" } = {
          method: req.method ?? "GET",
          headers: Object.fromEntries(
            Object.entries(req.headers).filter(
              (entry): entry is [string, string] =>
                typeof entry[1] === "string",
            ),
          ),
        };
        if (body.byteLength > 0) {
          init.body = new Uint8Array(body) as BodyInit;
          init.duplex = "half"; // undici requires this for Request bodies
        }
        const response = await registry.handler(new Request(url, init));
        res.writeHead(response.status, Object.fromEntries(response.headers));
        res.end(Buffer.from(await response.arrayBuffer()));
      })().catch((err: unknown) => {
        // Observable but still fail closed: the caller only ever sees a
        // generic 500, never the internal error's contents.
        onError(err);
        if (!res.headersSent) {
          res.writeHead(500, { "content-type": "application/json" });
        }
        res.end(JSON.stringify({ error: "internal error" }));
      });
    });
  });

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(options.port ?? 0, host, resolve);
  });
  const address = server.address();
  if (address === null || typeof address === "string") {
    throw new Error("dev registry: could not determine bound port");
  }
  const port = address.port;

  const sweepTimer = setInterval(
    () => registry.sweepExpired(),
    options.sweepIntervalMs ?? 60_000,
  );
  sweepTimer.unref();

  return {
    registry,
    server,
    port,
    url: `http://${host}:${port}`,
    close: async () => {
      clearInterval(sweepTimer);
      await new Promise<void>((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      });
    },
  };
}
