import { z } from "zod";

import { fromBase64Url } from "./bytes.js";

/**
 * ShareEnvelope schema per sharing-ux-blueprint.md §2.1, with the signed
 * typed resource selector and optional display.mode presentation hint from
 * sharing-viewer-and-registry.md §1. All objects are strict — unknown fields
 * are rejected everywhere.
 */

/** Strictly-decodable unpadded base64url: alphabet, length, AND zero trailing bits. */
function decodeBase64UrlOrNull(value: string): Uint8Array | null {
  try {
    return fromBase64Url(value);
  } catch {
    return null;
  }
}

const base64UrlString = () =>
  z.string().refine((value) => decodeBase64UrlOrNull(value) !== null, {
    message: "expected strictly-decodable unpadded base64url",
  });

/**
 * A canonical HTTPS web origin: `https://host[:non-default-port]` and nothing
 * else. No path, query, fragment, userinfo, trailing slash, default-port
 * alias (`:443`), or non-lowercase host — the string must round-trip exactly
 * through URL origin serialization. Rejects every non-https scheme
 * (http:, ftp:, file:, javascript:, …). This must byte-match what a Rust
 * verifier would accept, so it is exact-string, not "URL-ish".
 */
export function isCanonicalHttpsOrigin(value: string): boolean {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return false;
  }
  return url.protocol === "https:" && url.origin === value;
}

/**
 * Session JWK carried by bearer-target envelopes. Strict discriminated union
 * over the asymmetric private-key families a session key can be (OKP / EC).
 * The private component (`d`) is REQUIRED — a bearer envelope without it is
 * useless — and cross-family members (`y` on OKP, `k` anywhere) are rejected,
 * as are unknown JWK members, rather than silently signed over.
 */
const sessionJwkCommonFields = {
  alg: z.string().min(1).optional(),
  use: z.string().min(1).optional(),
  key_ops: z.array(z.string().min(1)).optional(),
  kid: z.string().min(1).optional(),
  ext: z.boolean().optional(),
};

const okpPrivateJwkSchema = z
  .object({
    kty: z.literal("OKP"),
    crv: z.string().min(1),
    x: base64UrlString(),
    d: base64UrlString(),
    ...sessionJwkCommonFields,
  })
  .strict();

const ecPrivateJwkSchema = z
  .object({
    kty: z.literal("EC"),
    crv: z.string().min(1),
    x: base64UrlString(),
    y: base64UrlString(),
    d: base64UrlString(),
    ...sessionJwkCommonFields,
  })
  .strict();

export const sessionJwkSchema = z.discriminatedUnion("kty", [
  okpPrivateJwkSchema,
  ecPrivateJwkSchema,
]);

export const policyTargetSchema = z
  .object({
    kind: z.literal("policy"),
    policyCid: z.string().min(1),
    /** Canonical policy bytes, base64url-encoded (bytes are not JSON). */
    policyBytes: base64UrlString(),
  })
  .strict();

export const bearerKeyTargetSchema = z
  .object({
    kind: z.literal("bearerKey"),
    sessionJwk: sessionJwkSchema,
  })
  .strict();

export const recipientDidTargetSchema = z
  .object({
    kind: z.literal("recipientDid"),
    did: z.string().regex(/^did:[a-z0-9]+:.+$/, "expected a DID"),
  })
  .strict();

/** Signed discriminated union — the target kind itself is signature-covered. */
export const authorizationTargetSchema = z.discriminatedUnion("kind", [
  policyTargetSchema,
  bearerKeyTargetSchema,
  recipientDidTargetSchema,
]);

export const resourceSelectorSchema = z
  .object({
    kind: z.union([z.literal("exact"), z.literal("prefix")]),
    path: z.string().min(1),
  })
  .strict();

export const targetSchema = z
  .object({
    origin: z.string().refine(isCanonicalHttpsOrigin, {
      message: "expected a canonical https origin (https://host[:port], nothing else)",
    }),
    nodeAudience: z.string().min(1),
    spaceId: z.string().min(1),
    resource: resourceSelectorSchema,
  })
  .strict();

export const displaySchema = z
  .object({
    senderName: z.string().optional(),
    filename: z.string().optional(),
    recipientHint: z.string().optional(),
    /**
     * Presentation preference only (viewer spec §1): may narrow, never widen;
     * capabilities always win.
     */
    mode: z.union([z.literal("document"), z.literal("source"), z.literal("folder")]).optional(),
  })
  .strict();

export const signatureSchema = z
  .object({
    /** did:key of the sender's ed25519 signing key. */
    signerDid: z.string().regex(/^did:key:z[1-9A-HJ-NP-Za-km-z]+$/, "expected a did:key"),
    algorithm: z.literal("Ed25519"),
    /** base64url-encoded ed25519 signature over the JCS bytes of all other fields. */
    value: z.string().refine((value) => decodeBase64UrlOrNull(value)?.length === 64, {
      message: "expected base64url decoding to exactly 64 bytes",
    }),
  })
  .strict();

/** Envelope body — every signature-covered field. */
export const unsignedShareEnvelopeSchema = z
  .object({
    version: z.literal(1),
    shareId: z.string().min(1),
    /** Full signed delegation chain, opaque serialized form. */
    delegation: z.string().min(1),
    authorizationTarget: authorizationTargetSchema,
    target: targetSchema,
    display: displaySchema,
    /** ISO 8601 UTC datetime. Advisory here; enforcement is the delegation's. */
    expiry: z.string().datetime(),
  })
  .strict();

export const shareEnvelopeSchema = unsignedShareEnvelopeSchema
  .extend({ signature: signatureSchema })
  .strict();

export type SessionJwk = z.infer<typeof sessionJwkSchema>;
export type PolicyTarget = z.infer<typeof policyTargetSchema>;
export type BearerKeyTarget = z.infer<typeof bearerKeyTargetSchema>;
export type RecipientDidTarget = z.infer<typeof recipientDidTargetSchema>;
export type AuthorizationTarget = z.infer<typeof authorizationTargetSchema>;
export type ResourceSelector = z.infer<typeof resourceSelectorSchema>;
export type ShareTarget = z.infer<typeof targetSchema>;
export type ShareDisplay = z.infer<typeof displaySchema>;
export type EnvelopeSignature = z.infer<typeof signatureSchema>;
export type UnsignedShareEnvelope = z.infer<typeof unsignedShareEnvelopeSchema>;
export type ShareEnvelope = z.infer<typeof shareEnvelopeSchema>;
