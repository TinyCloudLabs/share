import {
  base64UrlEncode,
  constantTimeEqual,
  hashDeleteToken,
  sha256,
} from "./encoding";
import { toBytes, type D1Database, type Env } from "./d1";
import { hitRateLimit } from "./ratelimit";
import { COMMON_HEADERS, jsonResponse, notFound, rateLimited, rawSealedResponse } from "./responses";
import { readLiveDeleteHash, readLiveLink, runCleanup, tombstoneLink } from "./store";

const PREFIX = "/api/share-links";
const ID_RE = /^[a-z2-7]{26}$/;
const TOKEN_RE = /^[A-Za-z0-9_-]{43}$/;
const IP_SALT = "tc1737-share-links-ip-v1";

function nowSecondsOf(nowMs: number): number {
  return Math.floor(nowMs / 1000);
}

function errorName(err: unknown): string {
  return err instanceof Error ? err.name : "unknown";
}

/** Expands an IPv6 literal into eight 16-bit groups, or returns null when it does not parse. */
function ipv6Groups(address: string): number[] | null {
  let s = address;
  const zone = s.indexOf("%");
  if (zone >= 0) {
    s = s.slice(0, zone);
  }
  const lastColon = s.lastIndexOf(":");
  const tail = s.slice(lastColon + 1);
  if (tail.includes(".")) {
    const octets = tail.split(".").map(Number);
    if (octets.length !== 4 || octets.some((o) => !Number.isInteger(o) || o < 0 || o > 255)) {
      return null;
    }
    const [a = 0, b = 0, c = 0, d = 0] = octets;
    s = `${s.slice(0, lastColon + 1)}${((a << 8) | b).toString(16)}:${((c << 8) | d).toString(16)}`;
  }
  const halves = s.split("::");
  if (halves.length > 2) {
    return null;
  }
  const head = halves[0] ? halves[0].split(":") : [];
  const rest = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  let parts: string[];
  if (halves.length === 2) {
    const fill = 8 - head.length - rest.length;
    if (fill < 1) {
      return null;
    }
    parts = [...head, ...new Array<string>(fill).fill("0"), ...rest];
  } else {
    parts = head;
  }
  if (parts.length !== 8 || !parts.every((p) => /^[0-9a-f]{1,4}$/.test(p))) {
    return null;
  }
  return parts.map((p) => parseInt(p, 16));
}

/**
 * Rate-limit key for a client address. IPv4 keys on the full address. IPv6 keys on
 * the first 64 bits, so one subscriber's addresses share a bucket. IPv4-mapped IPv6
 * is keyed as its IPv4 address. Unparseable input keys on the normalized string.
 */
function rateLimitKey(ip: string): string {
  const normalized = ip.trim().toLowerCase();
  if (!normalized.includes(":")) {
    return normalized;
  }
  const groups = ipv6Groups(normalized);
  if (groups === null) {
    return normalized;
  }
  const [g5 = 0, g6 = 0, g7 = 0] = groups.slice(5);
  if (groups.slice(0, 5).every((g) => g === 0) && g5 === 0xffff) {
    return `${g6 >> 8}.${g6 & 0xff}.${g7 >> 8}.${g7 & 0xff}`;
  }
  return `${groups
    .slice(0, 4)
    .map((g) => g.toString(16))
    .join(":")}::/64`;
}

async function clientIpHash(request: Request): Promise<string> {
  const key = rateLimitKey(request.headers.get("CF-Connecting-IP") ?? "unknown");
  const digest = await sha256(new TextEncoder().encode(key + IP_SALT));
  return base64UrlEncode(digest).slice(0, 16);
}

async function handleRead(request: Request, db: D1Database, id: string, nowMs: number): Promise<Response> {
  const nowSeconds = nowSecondsOf(nowMs);
  const decision = await hitRateLimit(db, "r", await clientIpHash(request), 120, 60, nowSeconds);
  if (!decision.allowed) {
    return rateLimited(decision.retryAfterSeconds);
  }
  const normalized = id.toLowerCase();
  if (!ID_RE.test(normalized)) {
    return notFound();
  }
  const row = await readLiveLink(db, normalized, nowSeconds);
  if (row === null) {
    return notFound();
  }
  return rawSealedResponse(
    toBytes(row.ciphertext),
    row.cid,
    new Date(row.expires_at * 1000).toISOString(),
  );
}

async function handleDelete(request: Request, db: D1Database, id: string, nowMs: number): Promise<Response> {
  const nowSeconds = nowSecondsOf(nowMs);
  const decision = await hitRateLimit(db, "x", await clientIpHash(request), 120, 60, nowSeconds);
  if (!decision.allowed) {
    return rateLimited(decision.retryAfterSeconds);
  }
  const normalized = id.toLowerCase();
  if (!ID_RE.test(normalized)) {
    return notFound();
  }
  const auth = request.headers.get("Authorization") ?? "";
  if (!auth.startsWith("Bearer ")) {
    return notFound();
  }
  const token = auth.slice("Bearer ".length);
  if (!TOKEN_RE.test(token)) {
    return notFound();
  }
  const storedHash = await readLiveDeleteHash(db, normalized, nowSeconds);
  if (storedHash === null) {
    return notFound();
  }
  const presentedHash = await hashDeleteToken(token);
  if (!constantTimeEqual(presentedHash, storedHash)) {
    return notFound();
  }
  const removed = await tombstoneLink(db, normalized, nowSeconds);
  if (!removed) {
    return notFound();
  }
  return new Response(null, { status: 204, headers: { ...COMMON_HEADERS } });
}

async function route(request: Request, env: Env, nowMs: number): Promise<Response> {
  const { pathname } = new URL(request.url);
  if (pathname === PREFIX) {
    // Creating links moved to the links API (api.tinycloud.xyz); this route only answers existing links until it is retired.
    return request.method === "POST" ? jsonResponse(410, { error: "gone" }) : notFound();
  }
  if (!pathname.startsWith(PREFIX + "/")) {
    return notFound();
  }
  const rest = pathname.slice(PREFIX.length + 1);
  if (rest.includes("/")) {
    return notFound();
  }
  if (request.method === "GET") {
    return handleRead(request, env.DB, rest, nowMs);
  }
  if (request.method === "DELETE") {
    return handleDelete(request, env.DB, rest, nowMs);
  }
  return notFound();
}

export async function handleRequest(request: Request, env: Env, nowMs: number): Promise<Response> {
  try {
    return await route(request, env, nowMs);
  } catch (err) {
    console.error("share-links internal", errorName(err));
    return jsonResponse(500, { error: "internal" });
  }
}

export async function handleScheduled(env: Env, nowMs: number): Promise<void> {
  await runCleanup(env.DB, nowSecondsOf(nowMs));
}
