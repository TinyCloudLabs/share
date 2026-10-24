import { addressBuckets } from "./address.ts";
import { base64UrlDecode, base64UrlEncode, constantTimeEqual, newLinkId, sha256, utf8, cidForBytes } from "./bytes.ts";
import {
  ID_ATTEMPTS,
  LIMITS,
  MIN_BODY_BYTES,
  NONCE_TTL_SECONDS,
  REQUEST_BODY_CAP_BYTES,
  MAX_LINK_BODY_BYTES,
  WINDOW_SECONDS,
  type FreePlan,
  type ServiceConfig,
  type WindowLimit,
} from "./config.ts";
import { verifyStrict } from "./ed25519.ts";
import {
  emptyResponse,
  isJsonContentType,
  jsonResponse,
  rawRecordResponse,
  readCappedBody,
  type CorsMode,
} from "./http.ts";
import { jcs } from "./jcs.ts";
import { hasDuplicateKey } from "./json-strict.ts";
import {
  DELETE_REQUEST_KEYS,
  LINK_ID_RE,
  checkIssuer,
  checkLife,
  hasExactKeys,
  isNonce,
  isPlainObject,
  parseHeader,
  parseSignature,
  parseTimestamp,
  type HeaderMode,
  type LinkHeader,
} from "./schemas.ts";
import type { LinkRecord, LinkStorage } from "./storage.ts";
import type { UsageTally } from "./usage.ts";

export const DOMAIN_HEADER = "xyz.tinycloud.links/header/v1\0";
export const DOMAIN_DELETE = "xyz.tinycloud.links/delete/v1\0";
const NONCE_SCOPE = "link";
const DELETE_BODY_CAP_BYTES = 8_192;
const API_KEY_RE = /^tlk_([A-Za-z0-9]{8})_([A-Za-z0-9_-]{43})$/;
const UNKNOWN_KEY_HASH = "0".repeat(43);

export type ErrorCode =
  | "invalid_request"
  | "invalid_signature"
  | "unauthorized"
  | "blocked"
  | "not_found"
  | "replayed"
  | "too_large"
  | "rate_limited"
  | "internal"
  | "capacity";

export const STATUS_BY_ERROR: Readonly<Record<ErrorCode, number>> = {
  invalid_request: 400,
  invalid_signature: 401,
  unauthorized: 401,
  blocked: 403,
  not_found: 404,
  replayed: 409,
  too_large: 413,
  rate_limited: 429,
  internal: 500,
  capacity: 503,
};

export interface UsageOptions {
  /** Free-plan limits to alert on; null for self-host (counters only, no limits). */
  readonly plan: FreePlan | null;
  /** D1 work counted by this isolate; null when the adapter reports none. */
  readonly tally: UsageTally | null;
  /** The live totals are computed on every Nth minute of the scheduled run. */
  readonly statsEveryMinutes: number;
}

export interface ServiceDeps {
  readonly storage: LinkStorage;
  readonly config: ServiceConfig;
  readonly usage: UsageOptions;
  /** Milliseconds since the epoch. */
  readonly now: () => number;
  /** One line per call; no content. */
  readonly log: (line: string) => void;
}

/** What a vector or test sees on top of the wire response; `reason` never leaves the process. */
export interface Outcome {
  readonly response: Response;
  readonly reason: string | null;
}

/** Rate-limit key builders; the keys carry no raw address. */
export const rateKeys = {
  issuerCreate: (issuer: string, windowSeconds: number) => `ic:${issuer}:${windowSeconds}`,
  issuerDelete: (issuer: string, windowSeconds: number) => `id:${issuer}:${windowSeconds}`,
  addressCreate: (rateHash: string, windowSeconds: number) => `ac:${rateHash}:${windowSeconds}`,
  addressRefused: (rateHash: string) => `ar:${rateHash}`,
  addressRead: (rateHash: string) => `ad:${rateHash}`,
  addressDelete: (rateHash: string) => `ax:${rateHash}`,
  apiKeyCreate: (keyId: string) => `kc:${keyId}`,
  apiKeyDelete: (keyId: string) => `kd:${keyId}`,
};

export async function addressHashes(
  config: ServiceConfig,
  address: string | null,
): Promise<{ readonly rateHash: string; readonly liveHash: string }> {
  const buckets = addressBuckets(address);
  const hash = async (label: string, key: string) =>
    base64UrlEncode(await sha256(utf8(`${config.addressSalt}|${label}|${key}`))).slice(0, 22);
  return { rateHash: await hash("rate", buckets.rateKey), liveHash: await hash("live", buckets.liveKey) };
}

interface RequestContext {
  readonly deps: ServiceDeps;
  readonly nowMs: number;
  readonly nowSeconds: number;
  readonly rateHash: string;
  readonly liveHash: string;
  readonly origin: string | null;
  readonly cors: CorsMode;
}

function errorBody(code: ErrorCode): { error: ErrorCode } {
  return { error: code };
}

async function countMetric(deps: ServiceDeps, name: string): Promise<void> {
  try {
    await deps.storage.count(name, 1);
  } catch (err) {
    deps.log(`links.metric_failed ${err instanceof Error ? err.name : "unknown"}`);
  }
}

async function refuse(
  ctx: RequestContext,
  code: ErrorCode,
  reason: string,
  extraHeaders: Record<string, string> = {},
  countAsRefused = false,
): Promise<Outcome> {
  if (countAsRefused) {
    // Requests refused before the signature check count against the per-address refusal limit.
    try {
      await ctx.deps.storage.hit(
        rateKeys.addressRefused(ctx.rateHash),
        LIMITS.addressRefused.limit,
        LIMITS.addressRefused.windowSeconds,
        ctx.nowSeconds,
      );
    } catch (err) {
      ctx.deps.log(`links.metric_failed ${err instanceof Error ? err.name : "unknown"}`);
    }
  }
  if (code !== "not_found" && code !== "internal") {
    await countMetric(ctx.deps, `rejects.${code}`);
  }
  const response = jsonResponse(STATUS_BY_ERROR[code], errorBody(code), ctx.cors, extraHeaders);
  return { response, reason };
}

async function earlyRefuse(ctx: RequestContext, code: ErrorCode, reason: string): Promise<Outcome> {
  return refuse(ctx, code, reason, {}, true);
}

function retryAfter(seconds: number): Record<string, string> {
  return { "Retry-After": String(seconds) };
}

/** Counts one hit per limit; the first refusal wins. */
async function hitAll(
  storage: LinkStorage,
  keyFor: (windowSeconds: number) => string,
  limits: readonly WindowLimit[],
  nowSeconds: number,
): Promise<number | null> {
  for (const limit of limits) {
    const result = await storage.hit(keyFor(limit.windowSeconds), limit.limit, limit.windowSeconds, nowSeconds);
    if (!result.allowed) {
      return result.retryAfter;
    }
  }
  return null;
}

async function addressLimits(
  ctx: RequestContext,
  limits: readonly WindowLimit[],
  keyFor: (rateHash: string, windowSeconds: number) => string,
  checkRefusedLimit: boolean,
): Promise<Outcome | null> {
  const { storage } = ctx.deps;
  if (checkRefusedLimit) {
    const refused = await storage.peek(
      rateKeys.addressRefused(ctx.rateHash),
      LIMITS.addressRefused.limit,
      LIMITS.addressRefused.windowSeconds,
      ctx.nowSeconds,
    );
    if (!refused.allowed) {
      return refuse(ctx, "rate_limited", "address_rate", retryAfter(refused.retryAfter));
    }
  }
  const wait = await hitAll(storage, (w) => keyFor(ctx.rateHash, w), limits, ctx.nowSeconds);
  return wait === null ? null : refuse(ctx, "rate_limited", "address_rate", retryAfter(wait));
}

function originOf(request: Request): string | null {
  return request.headers.get("Origin");
}

function corsForPost(origin: string | null, allowed: readonly string[]): CorsMode {
  return origin !== null && allowed.includes(origin) ? { kind: "origin", origin } : { kind: "none" };
}

/** The request body as a JSON object; null for text that is not JSON, not an object, or repeats a key at any depth. */
function parseJsonObject(bytes: Uint8Array): Record<string, unknown> | null {
  try {
    const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    if (hasDuplicateKey(text)) {
      return null;
    }
    const parsed: unknown = JSON.parse(text);
    return isPlainObject(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

function bearerOf(request: Request): string | null {
  const header = request.headers.get("Authorization");
  if (header === null) {
    return null;
  }
  const match = /^Bearer (.+)$/.exec(header);
  return match?.[1] ?? "";
}

async function signedBytesDigest(domain: string, value: unknown): Promise<Uint8Array> {
  return sha256(utf8(domain + jcs(value)));
}

async function verifySignature(
  domain: string,
  signed: unknown,
  signature: unknown,
  publicKey: Uint8Array | null,
): Promise<boolean> {
  const bytes = parseSignature(signature);
  if (bytes === null || publicKey === null) {
    return false;
  }
  return verifyStrict(publicKey, await signedBytesDigest(domain, signed), bytes);
}

type ApiKeyCheck =
  | { readonly ok: true; readonly keyId: string; readonly service: string; readonly allowedTypes: readonly string[] }
  | { readonly ok: false };

/** Unknown key id and wrong secret are the same refusal; the secret is only ever compared as a hash. */
async function checkApiKey(storage: LinkStorage, bearer: string): Promise<ApiKeyCheck> {
  const match = API_KEY_RE.exec(bearer);
  const record = match?.[1] ? await storage.apiKey(match[1]) : null;
  const secret = match?.[2] ?? "";
  const presented = base64UrlEncode(await sha256(utf8(secret)));
  const stored = record?.secretSha256 ?? UNKNOWN_KEY_HASH;
  const equal = constantTimeEqual(presented, stored);
  if (!match || !record || !equal) {
    return { ok: false };
  }
  return { ok: true, keyId: record.keyId, service: record.service, allowedTypes: record.allowedTypes };
}

// ---------------------------------------------------------------------------------------------
// create (contract 4.2)
// ---------------------------------------------------------------------------------------------

async function handleCreate(request: Request, ctx: RequestContext): Promise<Outcome> {
  const { deps } = ctx;
  const { storage, config } = deps;
  if (config.kill.create) {
    return refuse(ctx, "capacity", "kill_create", retryAfter(3600));
  }
  // 1. content type, body cap, JSON object
  if (!isJsonContentType(request.headers.get("Content-Type"))) {
    return earlyRefuse(ctx, "invalid_request", "content_type");
  }
  const raw = await readCappedBody(request, REQUEST_BODY_CAP_BYTES);
  if (raw === null) {
    return earlyRefuse(ctx, "too_large", "request_too_large");
  }
  const parsed = parseJsonObject(raw);
  if (parsed === null) {
    return earlyRefuse(ctx, "invalid_request", "request_shape");
  }
  // 2. origin, client address
  if (ctx.origin !== null && !config.corsOrigins.includes(ctx.origin)) {
    return earlyRefuse(ctx, "blocked", "origin_not_allowed");
  }
  if (await storage.isBlocked("address", ctx.liveHash)) {
    await countMetric(deps, "blocked.address");
    return refuse(ctx, "blocked", "address_blocked");
  }
  const limited = await addressLimits(ctx, LIMITS.addressCreate, rateKeys.addressCreate, true);
  if (limited !== null) {
    return limited;
  }
  // 3. top-level fields and credentials
  const signed = "signature" in parsed;
  if (!hasExactKeys(parsed, signed ? ["body", "header", "signature"] : ["body", "header"])) {
    return earlyRefuse(ctx, "invalid_request", "request_fields");
  }
  const bearer = bearerOf(request);
  if (signed && bearer !== null) {
    return earlyRefuse(ctx, "invalid_request", "auth_conflict");
  }
  if (!signed && bearer === null) {
    return earlyRefuse(ctx, "unauthorized", "no_credentials");
  }
  // 4. header shape and values
  const mode: HeaderMode = signed ? "signed" : "service";
  const headerResult = parseHeader(parsed["header"], mode, config.audience);
  if (!headerResult.ok) {
    return earlyRefuse(ctx, "invalid_request", headerResult.reason);
  }
  const header = headerResult.header;
  // 5. body
  const body = typeof parsed["body"] === "string" ? base64UrlDecode(parsed["body"]) : null;
  if (body === null) {
    return earlyRefuse(ctx, "invalid_request", "body_encoding");
  }
  if (body.length !== header.size) {
    return earlyRefuse(ctx, "invalid_request", "size_mismatch");
  }
  if (body.length > MAX_LINK_BODY_BYTES) {
    return earlyRefuse(ctx, "too_large", "body_over_cap");
  }
  if (body.length < MIN_BODY_BYTES) {
    return earlyRefuse(ctx, "invalid_request", "body_too_small");
  }
  if ((await cidForBytes(body)) !== header.bodyCid) {
    return earlyRefuse(ctx, "invalid_request", "body_hash_mismatch");
  }
  // 6. life and window
  const lifeProblem = checkLife(header, ctx.nowMs);
  if (lifeProblem !== null) {
    return earlyRefuse(ctx, "invalid_request", lifeProblem);
  }
  // 7. credentials
  let apiKeyId: string | null = null;
  if (signed) {
    if (!(await verifySignature(DOMAIN_HEADER, header, parsed["signature"], headerResult.issuerKey))) {
      return refuse(ctx, "invalid_signature", "bad_signature");
    }
  } else {
    const key = await checkApiKey(storage, bearer ?? "");
    if (!key.ok) {
      return refuse(ctx, "unauthorized", "bad_api_key");
    }
    if (header.issuer !== `service:${key.service}`) {
      return refuse(ctx, "invalid_request", "issuer_service_mismatch");
    }
    if (!key.allowedTypes.includes(header.type)) {
      return refuse(ctx, "invalid_request", "type_not_allowed_for_key");
    }
    apiKeyId = key.keyId;
  }
  // 8. block list
  if (await storage.isBlocked("issuer", header.issuer)) {
    await countMetric(deps, "blocked.issuer");
    return refuse(ctx, "blocked", "issuer_blocked");
  }
  // 9. per-issuer (or per-key) limits
  const wait =
    apiKeyId === null
      ? await hitAll(storage, (w) => rateKeys.issuerCreate(header.issuer, w), LIMITS.issuerCreate, ctx.nowSeconds)
      : await hitAll(storage, () => rateKeys.apiKeyCreate(apiKeyId), [LIMITS.apiKeyCreate], ctx.nowSeconds);
  if (wait !== null) {
    return refuse(ctx, "rate_limited", "issuer_rate", retryAfter(wait));
  }
  // 10. nonce
  const nonceHash = base64UrlEncode(await sha256(utf8(`${header.issuer}\n${header.nonce}`)));
  if (!(await storage.claimNonce(NONCE_SCOPE, nonceHash, NONCE_TTL_SECONDS, ctx.nowSeconds))) {
    return refuse(ctx, "replayed", "nonce_seen");
  }
  // 11. admission and insert
  return insertRecord(ctx, header, parsed["signature"], signed, body);
}

async function insertRecord(
  ctx: RequestContext,
  header: LinkHeader,
  signature: unknown,
  signed: boolean,
  body: Uint8Array,
): Promise<Outcome> {
  const { storage } = ctx.deps;
  const signatureText = signed && isPlainObject(signature) && typeof signature["value"] === "string" ? signature["value"] : null;
  for (let attempt = 0; attempt < ID_ATTEMPTS; attempt++) {
    const record: LinkRecord = {
      id: newLinkId(),
      type: header.type,
      issuer: header.issuer,
      issuedAt: Math.floor((parseTimestamp(header.issuedAt) ?? 0) / 1000),
      expiresAt: Math.floor((parseTimestamp(header.expiresAt) ?? 0) / 1000),
      size: body.length,
      bodyCid: header.bodyCid,
      headerJcs: jcs(header),
      signature: signatureText,
      body,
      addressHash: ctx.liveHash,
    };
    const outcome = await storage.put(record, ctx.nowSeconds);
    if (outcome === "ok") {
      await countMetric(ctx.deps, `creates.${header.type}`);
      return {
        response: jsonResponse(201, { id: record.id, expiresAt: header.expiresAt }, ctx.cors),
        reason: null,
      };
    }
    if (outcome !== "exists") {
      await countMetric(ctx.deps, `capacity.${outcome}`);
      return refuse(ctx, "capacity", outcome, retryAfter(3600));
    }
  }
  await countMetric(ctx.deps, "errors.internal");
  return refuse(ctx, "internal", "id_attempts");
}

// ---------------------------------------------------------------------------------------------
// read and take (contract 5)
// ---------------------------------------------------------------------------------------------

function recordHeader(record: LinkRecord): string {
  const signature = record.signature === null ? "" : `,"signature":{"algorithm":"Ed25519","value":"${record.signature}"}`;
  return base64UrlEncode(utf8(`{"header":${record.headerJcs}${signature}}`));
}

function notFound(ctx: RequestContext): Promise<Outcome> {
  return refuse(ctx, "not_found", "not_found");
}

async function handleRead(id: string, ctx: RequestContext, op: "read" | "take"): Promise<Outcome> {
  const { storage, config } = ctx.deps;
  if (config.kill[op]) {
    return refuse(ctx, "capacity", `kill_${op}`, retryAfter(3600));
  }
  const limited = await addressLimits(ctx, [LIMITS.addressRead], (hash) => rateKeys.addressRead(hash), false);
  if (limited !== null) {
    return limited;
  }
  const lower = id.toLowerCase();
  // One storage query serves unknown, expired, deleted and read-once ids alike.
  const record = LINK_ID_RE.test(lower)
    ? op === "read"
      ? await storage.get(lower, ctx.nowSeconds)
      : await storage.take(lower, ctx.nowSeconds)
    : null;
  if (record === null) {
    await countMetric(ctx.deps, "reads.miss");
    return notFound(ctx);
  }
  await countMetric(ctx.deps, "reads.hit");
  return { response: rawRecordResponse(record.body, recordHeader(record), ctx.cors), reason: null };
}

// ---------------------------------------------------------------------------------------------
// delete (contract 6)
// ---------------------------------------------------------------------------------------------

async function handleDelete(urlId: string, request: Request, ctx: RequestContext): Promise<Outcome> {
  const { deps } = ctx;
  const { storage, config } = deps;
  if (config.kill.delete) {
    return refuse(ctx, "capacity", "kill_delete", retryAfter(3600));
  }
  if (!isJsonContentType(request.headers.get("Content-Type"))) {
    return earlyRefuse(ctx, "invalid_request", "content_type");
  }
  const raw = await readCappedBody(request, DELETE_BODY_CAP_BYTES);
  if (raw === null) {
    return earlyRefuse(ctx, "too_large", "request_too_large");
  }
  const parsed = parseJsonObject(raw);
  if (parsed === null) {
    return earlyRefuse(ctx, "invalid_request", "request_shape");
  }
  if (ctx.origin !== null && !config.corsOrigins.includes(ctx.origin)) {
    return earlyRefuse(ctx, "blocked", "origin_not_allowed");
  }
  if (await storage.isBlocked("address", ctx.liveHash)) {
    await countMetric(deps, "blocked.address");
    return refuse(ctx, "blocked", "address_blocked");
  }
  const limited = await addressLimits(ctx, [LIMITS.addressDelete], (hash) => rateKeys.addressDelete(hash), true);
  if (limited !== null) {
    return limited;
  }
  const signed = "signature" in parsed;
  if (!hasExactKeys(parsed, signed ? ["request", "signature"] : ["request"])) {
    return earlyRefuse(ctx, "invalid_request", "request_fields");
  }
  const bearer = bearerOf(request);
  if (signed && bearer !== null) {
    return earlyRefuse(ctx, "invalid_request", "auth_conflict");
  }
  if (!signed && bearer === null) {
    return earlyRefuse(ctx, "unauthorized", "no_credentials");
  }
  const body = parsed["request"];
  if (!isPlainObject(body)) {
    return earlyRefuse(ctx, "invalid_request", "request_shape");
  }
  if (!hasExactKeys(body, DELETE_REQUEST_KEYS)) {
    return earlyRefuse(ctx, "invalid_request", "request_fields");
  }
  if (body["version"] !== 1 || body["op"] !== "delete") {
    return earlyRefuse(ctx, "invalid_request", "request_version");
  }
  const lowerUrlId = urlId.toLowerCase();
  if (!LINK_ID_RE.test(lowerUrlId)) {
    return earlyRefuse(ctx, "not_found", "id_grammar");
  }
  if (body["id"] !== lowerUrlId) {
    return earlyRefuse(ctx, "invalid_request", "id_mismatch");
  }
  const issuerResult = checkIssuer(body["issuer"], signed ? "signed" : "service");
  if (!issuerResult.ok) {
    return earlyRefuse(ctx, "invalid_request", issuerResult.reason);
  }
  const issuer = String(body["issuer"]);
  if (body["audience"] !== config.audience) {
    return earlyRefuse(ctx, "invalid_request", "audience_mismatch");
  }
  const issuedMs = parseTimestamp(body["issuedAt"]);
  if (issuedMs === null) {
    return earlyRefuse(ctx, "invalid_request", "timestamp_format");
  }
  if (!isNonce(body["nonce"])) {
    return earlyRefuse(ctx, "invalid_request", "nonce_format");
  }
  if (Math.abs(issuedMs - ctx.nowMs) > WINDOW_SECONDS * 1000) {
    return earlyRefuse(ctx, "invalid_request", "issued_at_window");
  }
  let apiKeyId: string | null = null;
  if (signed) {
    if (!(await verifySignature(DOMAIN_DELETE, body, parsed["signature"], issuerResult.publicKey))) {
      return refuse(ctx, "invalid_signature", "bad_signature");
    }
  } else {
    const key = await checkApiKey(storage, bearer ?? "");
    if (!key.ok) {
      return refuse(ctx, "unauthorized", "bad_api_key");
    }
    if (issuer !== `service:${key.service}`) {
      return refuse(ctx, "invalid_request", "issuer_service_mismatch");
    }
    apiKeyId = key.keyId;
  }
  const wait =
    apiKeyId === null
      ? await hitAll(storage, (w) => rateKeys.issuerDelete(issuer, w), LIMITS.issuerDelete, ctx.nowSeconds)
      : await hitAll(storage, () => rateKeys.apiKeyDelete(apiKeyId), [LIMITS.apiKeyDelete], ctx.nowSeconds);
  if (wait !== null) {
    return refuse(ctx, "rate_limited", "issuer_rate", retryAfter(wait));
  }
  const nonceHash = base64UrlEncode(await sha256(utf8(`${issuer}\n${String(body["nonce"])}`)));
  if (!(await storage.claimNonce(NONCE_SCOPE, nonceHash, NONCE_TTL_SECONDS, ctx.nowSeconds))) {
    return refuse(ctx, "replayed", "nonce_seen");
  }
  // Unknown, expired, deleted and issued-by-someone-else are one result.
  if (!(await storage.delete(lowerUrlId, issuer, ctx.nowSeconds))) {
    await countMetric(deps, "deletes.miss");
    return refuse(ctx, "not_found", "uniform");
  }
  await countMetric(deps, "deletes.ok");
  return { response: emptyResponse(204, ctx.cors), reason: null };
}

// ---------------------------------------------------------------------------------------------
// routing
// ---------------------------------------------------------------------------------------------

const PREFIX = "/v1/links";

function preflight(request: Request, allowed: readonly string[]): Response {
  const origin = originOf(request);
  if (origin === null) {
    return jsonResponse(404, errorBody("not_found"), { kind: "none" });
  }
  if (!allowed.includes(origin)) {
    return jsonResponse(403, errorBody("blocked"), { kind: "none" });
  }
  return new Response(null, {
    status: 204,
    headers: {
      "Cache-Control": "no-store",
      "Access-Control-Allow-Origin": origin,
      Vary: "Origin",
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
      "Access-Control-Max-Age": "600",
    },
  });
}

/** Routes one request. The clock and storage come from `deps`. Every request is counted once, here, before routing. */
export async function handleRequestWithReason(request: Request, deps: ServiceDeps): Promise<Outcome> {
  await countMetric(deps, "requests");
  const url = new URL(request.url);
  const { pathname } = url;
  const method = request.method;
  const none: CorsMode = { kind: "none" };
  const miss = (): Outcome => ({ response: jsonResponse(404, errorBody("not_found"), none), reason: "route" });
  if (pathname !== PREFIX && !pathname.startsWith(PREFIX + "/")) {
    return miss();
  }
  const segments = pathname === PREFIX ? [] : pathname.slice(PREFIX.length + 1).split("/");
  const [id, action] = segments;
  const isCreate = segments.length === 0;
  const isRead = segments.length === 1;
  const isTake = segments.length === 2 && action === "take";
  const isDelete = segments.length === 2 && action === "delete";
  if (method === "OPTIONS") {
    if (isCreate || isDelete) {
      return { response: preflight(request, deps.config.corsOrigins), reason: null };
    }
    return { response: isTake ? preflight(request, deps.config.takeOrigins) : miss().response, reason: null };
  }
  const nowMs = deps.now();
  const addresses = await addressHashes(deps.config, request.headers.get(deps.config.clientAddressHeader));
  const origin = originOf(request);
  let cors: CorsMode = none;
  if (method === "GET" && isRead) {
    cors = { kind: "open" };
  } else if (method === "POST" && (isCreate || isDelete)) {
    cors = corsForPost(origin, deps.config.corsOrigins);
  } else if (method === "POST" && isTake) {
    cors = corsForPost(origin, deps.config.takeOrigins);
  }
  const ctx: RequestContext = {
    deps,
    nowMs,
    nowSeconds: Math.floor(nowMs / 1000),
    rateHash: addresses.rateHash,
    liveHash: addresses.liveHash,
    origin,
    cors,
  };
  if (method === "POST" && isCreate) {
    return handleCreate(request, ctx);
  }
  if (method === "GET" && isRead && id !== undefined) {
    return handleRead(id, ctx, "read");
  }
  if (method === "POST" && isTake && id !== undefined) {
    return handleRead(id, ctx, "take");
  }
  if (method === "POST" && isDelete && id !== undefined) {
    return handleDelete(id, request, ctx);
  }
  return miss();
}

export async function handleRequest(request: Request, deps: ServiceDeps): Promise<Response> {
  try {
    return (await handleRequestWithReason(request, deps)).response;
  } catch (err) {
    deps.log(`links.internal ${err instanceof Error ? err.name : "unknown"}`);
    await countMetric(deps, "errors.internal");
    return jsonResponse(500, errorBody("internal"), { kind: "none" });
  }
}
