/**
 * Bearer-slice delegation binding check (viewer spec §1 "Mode detection").
 *
 * The UI must derive its mode from EFFECTIVE CAPABILITIES, never from the
 * envelope's unsigned hints — and never from the mere fact that the envelope
 * decrypted. This module STRUCTURALLY decodes the envelope's embedded
 * delegation (a UCAN/JWT-shaped token: three base64url segments,
 * header.payload.signature, capabilities in the payload's `att` array) and
 * fails closed unless ALL of the following hold:
 *
 *   1. the token parses (three non-empty base64url segments; header and
 *      payload are JSON objects; the signature segment decodes),
 *   2. the delegatee (`aud`) DID EQUALS the did:key derived from the
 *      envelope's embedded bearer sessionJwk — otherwise the key the link
 *      carries cannot use this delegation at all,
 *   3. some capability grants the read ability (`kv/get`, optionally
 *      namespaced `tinycloud.kv/get`) on a resource that covers the
 *      envelope's signed target (origin + spaceId + resource.path), either
 *      exactly or via a `/*` prefix.
 *
 * WHAT THIS DOES **NOT** DO — and must never be presented as doing:
 * cryptographic verification of the delegation chain (issuer signatures,
 * proof chain, revocation, delegation expiry/not-before). That verification
 * is the NODE's job at read time (stage 4); a client-side check can never be
 * the enforcement boundary because the client doesn't hold the chain roots.
 * This check makes the viewer honest — a link whose delegation cannot
 * possibly authorize its own embedded key is rejected before any
 * "read access" claim is shown — it does not make the link authorized.
 *
 * did:key derivation and base64url decoding are REUSED from
 * @tinycloud/share-envelope (no crypto re-implementation here).
 */
import {
  didKeyFromEd25519PublicKey,
  fromBase64Url,
  getBearerSessionJwk,
  type ShareEnvelope,
} from "@tinycloud/share-envelope";

/** Read abilities accepted for the single-file bearer viewer (spec §1 table). */
const READ_ABILITIES: ReadonlySet<string> = new Set(["kv/get", "tinycloud.kv/get"]);

export type DelegationCheckResult =
  | { ok: true; delegateeDid: string }
  | { ok: false; detail: string };

interface UcanCapability {
  readonly with: string;
  readonly can: string;
}

/** Strict base64url segment → JSON value, or null on ANY failure. */
function decodeJsonSegment(segment: string): unknown {
  try {
    const bytes = fromBase64Url(segment);
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    return null;
  }
}

function isJsonObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function parseCapability(value: unknown): UcanCapability | null {
  if (!isJsonObject(value)) return null;
  const withUri = value["with"];
  const can = value["can"];
  if (typeof withUri !== "string" || withUri.length === 0) return null;
  if (typeof can !== "string" || can.length === 0) return null;
  return { with: withUri, can };
}

/**
 * Does a granted resource URI cover the target resource URI? Exact match, or
 * a `<prefix>/*` grant whose prefix the target sits strictly under. Nothing
 * looser (no mid-segment globs, no scheme-relative tricks) — fail closed.
 */
function resourceCovers(granted: string, target: string): boolean {
  if (granted === target) return true;
  if (granted.endsWith("/*")) {
    const prefix = granted.slice(0, -1); // keep the trailing "/"
    return target.length > prefix.length && target.startsWith(prefix);
  }
  return false;
}

/**
 * The canonical resource URI the delegation must cover for this envelope:
 * `<origin>/<spaceId>/<resource.path>`. This is the BEARER-SLICE convention
 * shared by the viewer and its test vectors; stage 4 must align it with the
 * node's authoritative resource grammar before real reads ship.
 */
export function requiredResourceUri(envelope: ShareEnvelope): string {
  const { origin, spaceId, resource } = envelope.target;
  return `${origin}/${spaceId}/${resource.path}`;
}

/**
 * Structural bearer-binding check described in the module header. Returns a
 * failure `detail` suitable for logging/diagnostics — NOT for claiming what
 * was cryptographically proven.
 */
export function checkBearerDelegation(envelope: ShareEnvelope): DelegationCheckResult {
  // 1. Derive the did:key the embedded bearer key actually is. Only Ed25519
  //    OKP session keys are supported in this slice (the did:key helper is
  //    ed25519-only); anything else fails closed rather than guessing.
  let sessionDid: string;
  try {
    const jwk = getBearerSessionJwk(envelope);
    if (jwk.kty !== "OKP" || jwk.crv !== "Ed25519") {
      return {
        ok: false,
        detail: `unsupported bearer session key family ${jwk.kty}/${jwk.crv}; this build binds Ed25519 keys only`,
      };
    }
    sessionDid = didKeyFromEd25519PublicKey(fromBase64Url(jwk.x));
  } catch (error) {
    return {
      ok: false,
      detail: `could not derive did:key from embedded session key: ${
        error instanceof Error ? error.message : String(error)
      }`,
    };
  }

  // 2. Structural token decode: header.payload.signature.
  const segments = envelope.delegation.split(".");
  if (segments.length !== 3 || segments.some((segment) => segment.length === 0)) {
    return { ok: false, detail: "delegation is not a three-segment JWT-shaped token" };
  }
  const [headerSegment, payloadSegment, signatureSegment] = segments as [
    string,
    string,
    string,
  ];
  const header = decodeJsonSegment(headerSegment);
  if (!isJsonObject(header)) {
    return { ok: false, detail: "delegation header is not a base64url JSON object" };
  }
  const payload = decodeJsonSegment(payloadSegment);
  if (!isJsonObject(payload)) {
    return { ok: false, detail: "delegation payload is not a base64url JSON object" };
  }
  try {
    if (fromBase64Url(signatureSegment).length === 0) {
      return { ok: false, detail: "delegation signature segment is empty" };
    }
  } catch {
    return { ok: false, detail: "delegation signature segment is not base64url" };
  }

  // 3. Delegatee binding: aud must BE the embedded key's did:key.
  const audience = payload["aud"];
  if (typeof audience !== "string" || audience.length === 0) {
    return { ok: false, detail: "delegation payload has no audience (aud) DID" };
  }
  if (audience !== sessionDid) {
    return {
      ok: false,
      detail: "delegation audience is not the link's embedded session key",
    };
  }

  // 4. Capability coverage: some `att` entry must grant read on a resource
  //    covering the envelope's signed target.
  const att = payload["att"];
  if (!Array.isArray(att) || att.length === 0) {
    return { ok: false, detail: "delegation payload has no capabilities (att)" };
  }
  const required = requiredResourceUri(envelope);
  const granted = att
    .map(parseCapability)
    .some(
      (capability) =>
        capability !== null &&
        READ_ABILITIES.has(capability.can) &&
        resourceCovers(capability.with, required),
    );
  if (!granted) {
    return {
      ok: false,
      detail: `delegation grants no read capability covering ${required}`,
    };
  }

  return { ok: true, delegateeDid: audience };
}
