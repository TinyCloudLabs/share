import { z } from "zod";
import { base32LowerDecode, base32Lower, base64UrlDecode } from "./bytes.ts";
import {
  LINK_TYPES,
  MIN_LIFE_SECONDS,
  TYPE_CONFIG,
  WINDOW_SECONDS,
  type LinkType,
} from "./config.ts";
import { parseEd25519DidKey, pointProblem } from "./ed25519.ts";

/**
 * Typed schemas for the signed header (contract 2.2) and the delete request (6.1). A refusal is a
 * stable `reason` label used by tests; it is never sent on the wire.
 */

export type HeaderMode = "signed" | "service";

const AUDIENCE_RE = /^https:\/\/[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[0-9]{1,5})?$/;
const SERVICE_ISSUER_RE = /^service:[a-z0-9][a-z0-9-]{0,31}$/;
const NONCE_RE = /^[A-Za-z0-9_-]{22}$/;
const TIMESTAMP_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const CID_RE = /^bafkrei[a-z2-7]{52}$/;
export const LINK_ID_RE = /^[a-z2-7]{26}$/;
export const HEADER_KEYS = ["audience", "bodyCid", "expiresAt", "issuedAt", "issuer", "nonce", "size", "type", "version"];

export const DELETE_REQUEST_KEYS = ["audience", "id", "issuedAt", "issuer", "nonce", "op", "version"];

/** Milliseconds for a canonical `YYYY-MM-DDTHH:mm:ss.SSSZ` timestamp that round-trips; otherwise null. */
export function parseTimestamp(text: unknown): number | null {
  if (typeof text !== "string" || !TIMESTAMP_RE.test(text)) {
    return null;
  }
  const ms = Date.parse(text);
  return Number.isFinite(ms) && new Date(ms).toISOString() === text ? ms : null;
}

export function isNonce(text: unknown): boolean {
  return typeof text === "string" && NONCE_RE.test(text) && base64UrlDecode(text)?.length === 16;
}

export function isCanonicalRawCid(text: unknown): boolean {
  if (typeof text !== "string" || !CID_RE.test(text)) {
    return false;
  }
  const raw = base32LowerDecode(text.slice(1));
  return (
    raw !== null &&
    raw.length === 36 &&
    raw[0] === 0x01 &&
    raw[1] === 0x55 &&
    raw[2] === 0x12 &&
    raw[3] === 0x20 &&
    "b" + base32Lower(raw) === text
  );
}

export type IssuerCheck =
  | { readonly ok: true; readonly publicKey: Uint8Array | null }
  | { readonly ok: false; readonly reason: string };

/**
 * `signed`: an Ed25519 did:key of order l. `service`: `service:<name>`. A did:key issuer in service mode
 * and a service issuer in signed mode are each refused with their own reason.
 */
export function checkIssuer(issuer: unknown, mode: HeaderMode): IssuerCheck {
  if (typeof issuer !== "string") {
    return { ok: false, reason: "issuer_format" };
  }
  if (mode === "service") {
    return SERVICE_ISSUER_RE.test(issuer) ? { ok: true, publicKey: null } : { ok: false, reason: "issuer_service_format" };
  }
  if (!issuer.startsWith("did:key:")) {
    return { ok: false, reason: "issuer_method_not_allowed" };
  }
  const key = parseEd25519DidKey(issuer);
  if (!key.ok) {
    return { ok: false, reason: key.reason === "format" ? "issuer_format" : "issuer_key_type" };
  }
  const problem = pointProblem(key.publicKey);
  if (problem === "noncanonical") {
    return { ok: false, reason: "issuer_key_noncanonical" };
  }
  if (problem === "invalid") {
    return { ok: false, reason: "issuer_key_invalid" };
  }
  if (problem === "weak") {
    return { ok: false, reason: "issuer_weak_key" };
  }
  return { ok: true, publicKey: key.publicKey };
}

export interface LinkHeader {
  readonly version: 1;
  readonly type: LinkType;
  readonly issuer: string;
  readonly audience: string;
  readonly issuedAt: string;
  readonly expiresAt: string;
  readonly size: number;
  readonly bodyCid: string;
  readonly nonce: string;
}

function headerSchema(mode: HeaderMode, audience: string) {
  return z.strictObject({
    version: z.literal(1, { error: "header_version" }),
    type: z.string({ error: "unknown_type" }).refine((t) => (LINK_TYPES as readonly string[]).includes(t), {
      error: "unknown_type",
    }),
    issuer: z.string({ error: "issuer_format" }).superRefine((issuer, ctx) => {
      const checked = checkIssuer(issuer, mode);
      if (!checked.ok) {
        ctx.addIssue({ code: "custom", message: checked.reason });
      }
    }),
    audience: z.string({ error: "audience_format" }).superRefine((value, ctx) => {
      if (!AUDIENCE_RE.test(value)) {
        ctx.addIssue({ code: "custom", message: "audience_format" });
      } else if (value !== audience) {
        ctx.addIssue({ code: "custom", message: "audience_mismatch" });
      }
    }),
    issuedAt: z.string({ error: "timestamp_format" }).refine((t) => parseTimestamp(t) !== null, { error: "timestamp_format" }),
    expiresAt: z.string({ error: "timestamp_format" }).refine((t) => parseTimestamp(t) !== null, { error: "timestamp_format" }),
    nonce: z.string({ error: "nonce_format" }).refine(isNonce, { error: "nonce_format" }),
    size: z.number({ error: "size_format" }).int({ error: "size_format" }).min(1, { error: "size_format" }),
    bodyCid: z.string({ error: "body_cid_format" }).refine(isCanonicalRawCid, { error: "body_cid_format" }),
  });
}

export function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function hasExactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const keys = Object.keys(value).sort();
  return keys.length === expected.length && keys.every((k, i) => k === expected[i]);
}

export type HeaderParse =
  | { readonly ok: true; readonly header: LinkHeader; readonly issuerKey: Uint8Array | null }
  | { readonly ok: false; readonly reason: string };

/** Header structure and values: field set, version, type, issuer, audience, timestamps, nonce, size, bodyCid. */
export function parseHeader(raw: unknown, mode: HeaderMode, audience: string): HeaderParse {
  if (!isPlainObject(raw)) {
    return { ok: false, reason: "header_shape" };
  }
  if (!hasExactKeys(raw, HEADER_KEYS)) {
    return { ok: false, reason: "header_fields" };
  }
  const parsed = headerSchema(mode, audience).safeParse(raw);
  if (!parsed.success) {
    return { ok: false, reason: parsed.error.issues[0]?.message ?? "header_shape" };
  }
  const header = parsed.data as LinkHeader;
  const issuer = checkIssuer(header.issuer, mode);
  return { ok: true, header, issuerKey: issuer.ok ? issuer.publicKey : null };
}

/** Life rules, in order: window, expiry after issue, minimum, maximum for the type, not already expired (contract 3). */
export function checkLife(header: LinkHeader, nowMs: number): string | null {
  const issued = parseTimestamp(header.issuedAt) ?? 0;
  const expires = parseTimestamp(header.expiresAt) ?? 0;
  if (Math.abs(issued - nowMs) > WINDOW_SECONDS * 1000) {
    return "issued_at_window";
  }
  if (expires <= issued) {
    return "expires_before_issued";
  }
  const lifeSeconds = (expires - issued) / 1000;
  if (lifeSeconds < MIN_LIFE_SECONDS) {
    return "life_too_short";
  }
  if (lifeSeconds > TYPE_CONFIG[header.type].maxLifeSeconds) {
    return "life_too_long";
  }
  return expires <= nowMs ? "already_expired" : null;
}

export interface SignatureObject {
  readonly algorithm: "Ed25519";
  readonly value: string;
}

const signatureSchema = z.strictObject({
  algorithm: z.literal("Ed25519"),
  value: z.string().refine((s) => base64UrlDecode(s)?.length === 64),
});

/** The 64 signature bytes, or null when the object is not `{algorithm:"Ed25519", value:<86 chars>}`. */
export function parseSignature(raw: unknown): Uint8Array | null {
  const parsed = signatureSchema.safeParse(raw);
  return parsed.success ? base64UrlDecode(parsed.data.value) : null;
}

export interface DeleteRequest {
  readonly version: 1;
  readonly op: "delete";
  readonly id: string;
  readonly issuer: string;
  readonly audience: string;
  readonly issuedAt: string;
  readonly nonce: string;
}
