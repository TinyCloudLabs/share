/**
 * A local, in-memory stand-in for the links API (contract sections 4 to 6), used only by tests and the
 * browser run. It answers the same requests the real service answers and is checked against the
 * contract's service vectors (`create`, `delete`, `read`). It is not shipped.
 */
import { sha256 } from "@noble/hashes/sha256";
import { canonicalize, computeCid, fromBase64Url, toBase64Url } from "@tinycloud/share-envelope";
import { checkHeader, DELETE_DOMAIN, HEADER_DOMAIN, issuerKey, LINK_TYPES, MIN_BODY_BYTES, MIN_LIFE_SECONDS, verifySignature, type LinkHeader } from "../../src/short-links/record.js";

const WINDOW_MS = 120_000;
const ID_ALPHABET = "abcdefghijklmnopqrstuvwxyz234567";
const ID = /^[a-z2-7]{26}$/;
const NONCE = /^[A-Za-z0-9_-]{22}$/;
const SERVICE_ISSUER = /^service:[a-z0-9][a-z0-9-]{0,31}$/;
const REQUEST_CAP_BYTES = 177_835;

export interface MockApiKey {
  readonly keyId: string;
  readonly service: string;
  readonly allowedTypes: readonly string[];
  readonly secretSha256: string;
}

export interface StoredLink {
  readonly type: string;
  readonly issuer: string;
  readonly expiresAt: string;
  readonly headerJcs?: string;
  readonly signature?: unknown;
  readonly body?: Uint8Array;
}

export interface MockLinksState {
  /** `<issuer>\n<nonce>` pairs already used. */
  seenNonces: Set<string>;
  blockedIssuers: Set<string>;
  issuerRateLimited: boolean;
  capacityFull: boolean;
  addressBlocked: boolean;
  addressRateLimited: boolean;
  addressLiveFull: boolean;
  records: Map<string, StoredLink>;
}

export interface MockLinksOptions {
  readonly now: () => number;
  readonly audience: string;
  /** Origins whose browsers may POST (contract 4.10). */
  readonly corsOrigins: readonly string[];
  readonly apiKeys?: readonly MockApiKey[];
}

export interface MockRequest {
  readonly method: string;
  readonly path: string;
  readonly headers: Readonly<Record<string, string>>;
  readonly body?: string;
}

function error(status: number, code: string, extra: Record<string, string> = {}): Response {
  return new Response(JSON.stringify({ error: code }), { status, headers: { "content-type": "application/json", "cache-control": "no-store", ...extra } });
}

const iso = (ms: number): string => new Date(ms).toISOString();

function timestamp(value: unknown): number | undefined {
  if (typeof value !== "string") return undefined;
  const ms = Date.parse(value);
  return Number.isFinite(ms) && iso(ms) === value ? ms : undefined;
}

function strictBytes(text: unknown): Uint8Array | undefined {
  if (typeof text !== "string") return undefined;
  try {
    return fromBase64Url(text);
  } catch {
    return undefined;
  }
}

function newId(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(26));
  return [...bytes].map((byte) => ID_ALPHABET[byte % 32]).join("");
}

export function createMockLinksApi(options: MockLinksOptions) {
  const state: MockLinksState = {
    seenNonces: new Set(), blockedIssuers: new Set(), issuerRateLimited: false, capacityFull: false,
    addressBlocked: false, addressRateLimited: false, addressLiveFull: false, records: new Map(),
  };
  const apiKeys = options.apiKeys ?? [];
  /** Request log, for tests that assert what the service was sent. */
  const received: { readonly method: string; readonly path: string; readonly body: string }[] = [];

  const corsFor = (origin: string | undefined, method: string): Record<string, string> => {
    if (method === "GET") return { "access-control-allow-origin": "*", "access-control-expose-headers": "X-Link-Record" };
    return origin !== undefined && options.corsOrigins.includes(origin)
      ? { "access-control-allow-origin": origin, vary: "Origin" }
      : {};
  };

  /** The credentials of a request: a signature in the body, or an API key. `undefined` is a refusal already answered. */
  function bearerKey(authorization: string | undefined): { readonly key?: MockApiKey; readonly bad: boolean } | undefined {
    if (authorization === undefined) return undefined;
    const match = /^Bearer tlk_([A-Za-z0-9]{8})_([A-Za-z0-9_-]{43})$/.exec(authorization);
    const key = match === null ? undefined : apiKeys.find((candidate) => candidate.keyId === match[1]);
    if (match === null || key === undefined || toBase64Url(sha256(new TextEncoder().encode(match[2]!))) !== key.secretSha256) return { bad: true };
    return { key, bad: false };
  }

  function preflight(request: MockRequest): Response | undefined {
    const { origin } = request.headers;
    if (origin !== undefined && !options.corsOrigins.includes(origin)) return error(403, "blocked");
    if (state.addressBlocked) return error(403, "blocked");
    if (state.addressRateLimited) return error(429, "rate_limited", { "retry-after": "60" });
    return undefined;
  }

  async function create(request: MockRequest): Promise<Response> {
    if (request.headers["content-type"]?.split(";")[0]?.trim() !== "application/json") return error(400, "invalid_request");
    if ((request.body ?? "").length > REQUEST_CAP_BYTES) return error(413, "too_large");
    let parsed: unknown;
    try {
      parsed = JSON.parse(request.body ?? "");
    } catch {
      return error(400, "invalid_request");
    }
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return error(400, "invalid_request");
    const early = preflight(request);
    if (early !== undefined) return early;
    const fields = Object.keys(parsed).sort().join(",");
    if (fields !== "body,header" && fields !== "body,header,signature") return error(400, "invalid_request");
    const { header, signature, body } = parsed as { header: unknown; signature?: unknown; body: unknown };
    const signed = signature !== undefined;
    const bearer = bearerKey(request.headers["authorization"]);
    if (signed && request.headers["authorization"] !== undefined) return error(400, "invalid_request");
    if (!signed && bearer === undefined) return error(401, "unauthorized");
    const checked = checkHeader(header, signed);
    if ("refusal" in checked) return error(400, "invalid_request");
    const h: LinkHeader = checked.header;
    if (h.audience !== options.audience) return error(400, "invalid_request");
    const bytes = strictBytes(body);
    if (bytes === undefined || bytes.byteLength !== h.size) return error(400, "invalid_request");
    if (bytes.byteLength > LINK_TYPES[h.type].maxBody) return error(413, "too_large");
    if (bytes.byteLength < MIN_BODY_BYTES || (await computeCid(bytes)) !== h.bodyCid) return error(400, "invalid_request");
    const issued = timestamp(h.issuedAt)!;
    const expires = timestamp(h.expiresAt)!;
    const now = options.now();
    const lifeSeconds = (expires - issued) / 1000;
    if (Math.abs(issued - now) > WINDOW_MS || expires <= issued || lifeSeconds < MIN_LIFE_SECONDS || lifeSeconds > LINK_TYPES[h.type].maxLifeSeconds || expires <= now) return error(400, "invalid_request");
    if (signed) {
      if (!verifySignature(HEADER_DOMAIN, h, h.issuer, signature)) return error(401, "invalid_signature");
    } else {
      if (bearer?.bad === true || bearer?.key === undefined) return error(401, "unauthorized");
      if (h.issuer !== `service:${bearer.key.service}` || !bearer.key.allowedTypes.includes(h.type)) return error(400, "invalid_request");
    }
    if (state.blockedIssuers.has(h.issuer)) return error(403, "blocked");
    if (state.issuerRateLimited) return error(429, "rate_limited", { "retry-after": "60" });
    if (state.seenNonces.has(`${h.issuer}\n${h.nonce}`)) return error(409, "replayed");
    if (state.addressLiveFull || state.capacityFull) return error(503, "capacity", { "retry-after": "3600" });
    state.seenNonces.add(`${h.issuer}\n${h.nonce}`);
    const id = newId();
    state.records.set(id, { type: h.type, issuer: h.issuer, expiresAt: h.expiresAt, headerJcs: canonicalize(h), ...(signed ? { signature } : {}), body: bytes });
    return new Response(JSON.stringify({ id, expiresAt: h.expiresAt }), { status: 201, headers: { "content-type": "application/json", "cache-control": "no-store" } });
  }

  function remove(request: MockRequest, urlId: string): Response {
    const early = preflight(request);
    if (early !== undefined) return early;
    let parsed: unknown;
    try {
      parsed = JSON.parse(request.body ?? "");
    } catch {
      return error(400, "invalid_request");
    }
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return error(400, "invalid_request");
    const fields = Object.keys(parsed).sort().join(",");
    if (fields !== "request,signature" && fields !== "request") return error(400, "invalid_request");
    const { request: r, signature } = parsed as { request: Record<string, unknown>; signature?: unknown };
    const signed = signature !== undefined;
    const bearer = bearerKey(request.headers["authorization"]);
    if (signed && request.headers["authorization"] !== undefined) return error(400, "invalid_request");
    if (!signed && bearer === undefined) return error(401, "unauthorized");
    if (typeof r !== "object" || r === null || Array.isArray(r)) return error(400, "invalid_request");
    const want = ["audience", "id", "issuedAt", "issuer", "nonce", "op", "version"];
    const keys = Object.keys(r).sort();
    if (keys.length !== want.length || keys.some((key, index) => key !== want[index])) return error(400, "invalid_request");
    if (r["version"] !== 1 || r["op"] !== "delete") return error(400, "invalid_request");
    const lowered = urlId.toLowerCase();
    if (!ID.test(lowered)) return error(404, "not_found");
    if (r["id"] !== lowered) return error(400, "invalid_request");
    const issuer = r["issuer"];
    if (typeof issuer !== "string") return error(400, "invalid_request");
    if (signed) {
      if ("refusal" in issuerKey(issuer)) return error(400, "invalid_request");
    } else if (!SERVICE_ISSUER.test(issuer)) {
      return error(400, "invalid_request");
    }
    if (r["audience"] !== options.audience) return error(400, "invalid_request");
    const issued = timestamp(r["issuedAt"]);
    const nonce = r["nonce"];
    if (issued === undefined || typeof nonce !== "string" || !NONCE.test(nonce) || strictBytes(nonce)?.length !== 16) return error(400, "invalid_request");
    const now = options.now();
    if (Math.abs(issued - now) > WINDOW_MS) return error(400, "invalid_request");
    if (signed) {
      if (!verifySignature(DELETE_DOMAIN, r, issuer, signature)) return error(401, "invalid_signature");
    } else {
      if (bearer?.bad === true || bearer?.key === undefined) return error(401, "unauthorized");
      if (issuer !== `service:${bearer.key.service}`) return error(400, "invalid_request");
    }
    if (state.seenNonces.has(`${issuer}\n${nonce}`)) return error(409, "replayed");
    state.seenNonces.add(`${issuer}\n${nonce}`);
    const stored = state.records.get(lowered);
    if (stored === undefined || (timestamp(stored.expiresAt) ?? 0) <= now || stored.issuer !== issuer) return error(404, "not_found");
    state.records.delete(lowered);
    return new Response(null, { status: 204, headers: { "cache-control": "no-store" } });
  }

  function serve(id: string, readOnce: boolean, origin: string | undefined, method: string): Response {
    const stored = state.records.get(id.toLowerCase());
    const gone = (): Response => error(404, "not_found", { "x-content-type-options": "nosniff", ...corsFor(origin, method) });
    if (!ID.test(id.toLowerCase()) || stored === undefined || stored.body === undefined || (timestamp(stored.expiresAt) ?? 0) <= options.now()) return gone();
    if ((stored.type === "openkey-login") !== readOnce) return gone();
    if (readOnce) state.records.delete(id.toLowerCase());
    const meta = { header: JSON.parse(stored.headerJcs ?? "{}") as unknown, ...(stored.signature === undefined ? {} : { signature: stored.signature }) };
    return new Response(stored.body as BodyInit, {
      status: 200,
      headers: {
        "content-type": "application/octet-stream",
        "content-disposition": 'attachment; filename="link.bin"',
        "x-content-type-options": "nosniff",
        "content-security-policy": "default-src 'none'; sandbox",
        "cross-origin-resource-policy": "same-site",
        "cache-control": "no-store",
        "x-link-record": toBase64Url(new TextEncoder().encode(canonicalize(meta))),
        ...corsFor(origin, method),
      },
    });
  }

  async function handle(request: MockRequest): Promise<Response> {
    received.push({ method: request.method, path: request.path, body: request.body ?? "" });
    const { origin } = request.headers;
    if (request.method === "OPTIONS") {
      if (origin === undefined || !options.corsOrigins.includes(origin)) return new Response(null, { status: 403 });
      return new Response(null, { status: 204, headers: { ...corsFor(origin, "POST"), "access-control-allow-methods": "POST, OPTIONS", "access-control-allow-headers": "Content-Type", "access-control-max-age": "600" } });
    }
    const withCors = (response: Response, method: string): Response => {
      for (const [name, value] of Object.entries(corsFor(origin, method))) if (!response.headers.has(name)) response.headers.set(name, value);
      return response;
    };
    if (request.path === "/v1/links" && request.method === "POST") return withCors(await create(request), "POST");
    const match = /^\/v1\/links\/([^/]+)(\/delete|\/take)?$/.exec(request.path);
    if (match === null) return error(404, "not_found");
    if (match[2] === "/delete" && request.method === "POST") return withCors(remove(request, match[1]!), "POST");
    if (match[2] === "/take" && request.method === "POST") return serve(match[1]!, true, undefined, "POST");
    if (match[2] === undefined && request.method === "GET") return serve(match[1]!, false, origin, "GET");
    return error(404, "not_found");
  }

  /** A `fetch` that routes requests whose URL starts with `apiOrigin` to this service. `origin` is the page's origin. */
  function fetchFor(apiOrigin: string, pageOrigin?: string): typeof fetch {
    return (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = new URL(typeof input === "string" || input instanceof URL ? input : input.url);
      if (url.origin !== apiOrigin) throw new TypeError(`unexpected request to ${url.origin}`);
      const headers: Record<string, string> = {};
      for (const [name, value] of Object.entries((init?.headers ?? {}) as Record<string, string>)) headers[name.toLowerCase()] = value;
      if (pageOrigin !== undefined && (init?.method ?? "GET") !== "GET") headers["origin"] = pageOrigin;
      return handle({ method: init?.method ?? "GET", path: url.pathname, headers, ...(typeof init?.body === "string" ? { body: init.body } : {}) });
    }) as typeof fetch;
  }

  return { state, handle, fetchFor, received };
}
