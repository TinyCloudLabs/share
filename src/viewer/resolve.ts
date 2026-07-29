/**
 * Stage-3 viewer resolve + verify pipeline (bearer slice).
 *
 * Reuses the stage-1/2 packages for ALL crypto/CID/registry work — nothing
 * cryptographic is reimplemented here. The pipeline, in order, failing
 * closed at every step (specs/sharing-ux-blueprint.md §2.1: verify
 * "before sending anything anywhere"):
 *
 *   1. parseShareUrl(href)                 → { ciphertextCid, key32 }
 *   2. fetchBlob(registry, ciphertextCid)  → sealed blob (client re-verifies
 *      the CID internally; a lying gateway throws CidMismatchError)
 *   3. open(blob, key32)                   → plaintext envelope bytes
 *      (AES-256-GCM; wrong key / tampering throws)
 *   4. JSON.parse + strict schema parse    → ShareEnvelope
 *   5. switch on authorizationTarget.kind  → this stage handles ONLY
 *      "bearerKey"; policy / recipientDid are honest "unsupported" states
 *      (viewer spec §1: mode detection switches on the discriminated
 *      target before anything else)
 *   6. verifyEnvelope                      → BEARER MODE: the expected
 *      signer is the envelope's OWN signerDid — see the long note below
 *   7. resource selector                   → only { kind: "exact" } in this
 *      slice (single-file viewer); prefix/folder is a later stage
 *   8. expiry                              → fail closed on a dead share
 *      before any capability claim is evaluated
 *   9. checkBearerDelegation               → the embedded delegation must be
 *      a decodable token, EdDSA-signed by its own iss (verified), unexpired
 *      (exp required, nbf honored), whose delegatee IS the embedded session
 *      key's did:key and whose capabilities cover the signed target with
 *      read on canonical segment boundaries (viewer spec §1: mode derives
 *      from EFFECTIVE capabilities; a garbage delegation must never reach a
 *      "grants read access" UI)
 *  10. content (stage 4, bearer only)      → if the SIGNED envelope carries a
 *      `content` pointer, fetch that sealed blob from the registry (CID
 *      re-verified), decrypt it with the pointer's own key, and return the
 *      text for rendering. This direct registry fetch is a BEARER-SLICE
 *      mechanism — possession of the link is the read authority. In the
 *      policy/recipient-DID slices this step is replaced by a
 *      capability-gated read from the node named in `target`, and envelopes
 *      carry no content pointer. Fail closed: CID mismatch, AEAD failure,
 *      or non-UTF-8 plaintext all block rendering entirely.
 *
 * The fragment key exists only as an argument through steps 1-3 and is
 * zeroed on EVERY return path out of this function — success and each error
 * alike. It is never logged, stored, or sent anywhere (fragments never
 * leave the client by construction; main.ts scrubs location.hash/history
 * before this pipeline runs).
 */
import {
  fromBase64Url,
  computeCid,
  open,
  parseCompactOrInlineShareUrl,
  shareEnvelopeSchema,
  shareEnvelopeV2Schema,
  verifyEnvelope,
  type ShareEnvelope,
  type ShareEnvelopeV2,
} from "@tinycloud/share-envelope";
import {
  CidMismatchError,
  RegistryHttpError,
  fetchBlob,
} from "@tinycloud/share-registry";
import { checkBearerDelegation, parseAddressedEnvelope } from "@tinycloud/share-sdk";

/** Why a structurally valid envelope cannot be shown by THIS build. */
export type UnsupportedReason =
  | "policy-target"
  | "recipient-did-target"
  | "prefix-resource";

export type ResolveResult =
  /**
   * Verified bearer single-file share. `senderVerified` is ALWAYS false in
   * bearer mode — see the note in `resolveShare` — and the UI must render
   * the sender as "unverified", never with a checkmark. `content` is the
   * decrypted, CID-verified file text when the signed envelope carries a
   * content pointer (stage 4); absent for pointer-less envelopes.
   */
  | { state: "ok"; access?: "bearer" | "policy"; envelope: ShareEnvelope; senderVerified: boolean; content?: string; contentBytes?: Uint8Array }
  /** The URL is not a well-formed /s/<cid>#k= share link. */
  | { state: "invalid-link"; detail: string }
  /** Registry unreachable / blob missing (deleted, expired, never existed). */
  | { state: "fetch-failed"; detail: string }
  /** Registry returned bytes that do not hash to the link's CID. */
  | { state: "cid-mismatch" }
  /** AEAD failure: wrong/absent key, or tampered sealed blob. */
  | { state: "decrypt-failed" }
  /** Decrypted plaintext is not a strict-schema ShareEnvelope. */
  | { state: "envelope-invalid" }
  /** Sender signature did not verify. Nothing may be rendered. */
  | { state: "signature-invalid" }
  /**
   * The embedded delegation cannot authorize this link: it is not a
   * decodable token, its delegatee is not the embedded session key, or it
   * grants no read capability covering the signed target. Nothing may be
   * rendered (viewer spec §1: UI derives from effective capabilities).
   */
  | { state: "capability-invalid"; detail: string }
  /** Envelope expiry is in the past. */
  | { state: "expired"; envelope: ShareEnvelope }
  | { state: "policy-email-claim-required"; envelope: ShareEnvelope; shareCid: string; policy: Record<string, unknown> }
  | { state: "policy-v2-claim-required"; envelope: ShareEnvelopeV2; shareCid: string; policy: Record<string, unknown> }
  /** Signed content pointer present, but the registry couldn't serve the blob. */
  | { state: "content-fetch-failed"; detail: string }
  /**
   * Signed content pointer present, but the fetched bytes failed
   * verification: CID mismatch, AEAD (wrong key / tampering), or
   * non-UTF-8 plaintext. Nothing may be rendered.
   */
  | { state: "content-integrity-failed" }
  /** Valid envelope, but not a bearer + exact-path share (later stages). */
  | { state: "unsupported"; reason: UnsupportedReason; envelope: ShareEnvelope };

export interface ResolveShareOptions {
  /** Registry base URL (see config.ts for the app default). */
  registryBaseUrl: string;
  /** Fetch override — tests inject the in-process dev-registry handler. */
  fetchFn?: typeof globalThis.fetch;
  /** Clock override for the expiry check; defaults to Date.now(). */
  now?: () => number;
  /**
   * Observability hook: receives the freshly parsed fragment-key buffer.
   * Exists so tests can assert the key-hygiene contract (the buffer is
   * zeroed on every return path). Never use it to copy the key.
   */
  onKeyParsed?: (key32: Uint8Array) => void;
}

export async function resolveShare(
  href: string,
  options: ResolveShareOptions,
): Promise<ResolveResult> {
  // 1. Parse the link. The key comes from the FRAGMENT only; parseShareUrl
  //    already rejects query strings, userinfo, and non-canonical CIDs.
  let ciphertextCid: string;
  let linkOrigin: string;
  let key32: Uint8Array | undefined;
  let inlineBlob: Uint8Array | undefined;
  try {
    const parsed = parseCompactOrInlineShareUrl(href);
    ciphertextCid = parsed.ciphertextCid;
    linkOrigin = new URL(href).origin;
    key32 = parsed.key32;
    if (parsed.kind === "inline") inlineBlob = parsed.ciphertext;
  } catch (error) {
    return { state: "invalid-link", detail: "share link format is invalid" };
  }
  if (key32 !== undefined) options.onKeyParsed?.(key32);

  try {
    // 2. Fetch the sealed blob. fetchBlob re-verifies the CID of every
    //    received byte (trustless gateway posture) before returning.
    let blob: Uint8Array;
    try {
      if (inlineBlob !== undefined) {
        if (await computeCid(inlineBlob) !== ciphertextCid) return { state: "cid-mismatch" };
        blob = inlineBlob;
      } else {
        blob = await fetchBlob(options.registryBaseUrl, ciphertextCid, {
          ...(options.fetchFn !== undefined ? { fetchFn: options.fetchFn } : {}),
        });
      }
    } catch (error) {
      if (error instanceof CidMismatchError) return { state: "cid-mismatch" };
      if (error instanceof RegistryHttpError) {
        return { state: "fetch-failed", detail: `registry returned ${error.status}` };
      }
      return { state: "fetch-failed", detail: "registry unavailable" };
    }

    // 3. Decrypt. Any AEAD failure (wrong key, tampering that survived a
    //    correct CID — impossible from the network, but fail closed anyway)
    //    lands here.
    let plaintext: Uint8Array;
    try {
      plaintext = key32 === undefined ? blob : await open(blob, key32);
    } catch {
      return { state: "decrypt-failed" };
    }

    // 4. Bytes → JSON → strict schema. Unknown fields, missing fields, or
    //    malformed values are all rejected by the zod schema.
    let envelope: ShareEnvelope;
    try {
      const value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(plaintext)) as { readonly version?: unknown };
      if (value.version === 2) {
        const v2 = shareEnvelopeV2Schema.parse(value);
        if (v2.authorizationTarget.kind !== "policy") return { state: "unsupported", reason: "recipient-did-target", envelope: v2 as unknown as ShareEnvelope };
        let policy: Record<string, unknown>;
        try { policy = (await parseAddressedEnvelope(v2)).policy; } catch { return { state: "envelope-invalid" }; }
        if (Date.parse(v2.expiry) <= (options.now?.() ?? Date.now())) return { state: "expired", envelope: v2 as unknown as ShareEnvelope };
        return { state: "policy-v2-claim-required", envelope: v2, shareCid: ciphertextCid, policy };
      }
      envelope = shareEnvelopeSchema.parse(value);
    } catch {
      return { state: "envelope-invalid" };
    }

    // 5. Mode detection: switch on the signed discriminated target FIRST
    //    (viewer spec §1). This stage implements only the bearer path; the
    //    others get an honest "unsupported" — we do NOT fake verification
    //    for them (there is no expected signer to verify against yet).
    if (envelope.authorizationTarget.kind === "policy") {
      let policy: Record<string, unknown>;
      try {
        const parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(fromBase64Url(envelope.authorizationTarget.policyBytes))) as unknown;
        if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) throw new Error("invalid policy");
        policy = parsed as Record<string, unknown>;
        if (policy["type"] !== "TinyCloudSharePolicy" || policy["version"] !== 1 || typeof policy["issuerDid"] !== "string" || typeof policy["recipientEmail"] !== "string") throw new Error("invalid policy");
      } catch { return { state: "unsupported", reason: "policy-target", envelope }; }
      let verified = false;
      try { verified = await verifyEnvelope(envelope, { expectedSignerDid: String(policy["issuerDid"]) }); } catch { verified = false; }
      if (!verified) return { state: "signature-invalid" };
      if (envelope.target.resource.kind !== "exact") return { state: "unsupported", reason: "prefix-resource", envelope };
      const now = options.now?.() ?? Date.now();
      if (Date.parse(envelope.expiry) <= now) return { state: "expired", envelope };
      return { state: "policy-email-claim-required", envelope, shareCid: ciphertextCid, policy };
    }
    if (envelope.authorizationTarget.kind === "recipientDid") {
      return { state: "unsupported", reason: "recipient-did-target", envelope };
    }

    // 6. BEARER MODE VERIFICATION NOTE. verifyEnvelope requires an
    //    expectedSignerDid the caller already trusts. For a bearer share
    //    there is no out-of-band sender identity: trust comes from
    //    POSSESSION OF THE LINK, not from who signed the envelope, and the
    //    sender may legitimately be self-issued. So — for the bearer target
    //    ONLY — we pass the envelope's own signerDid as the expected
    //    signer. That still buys real integrity: the signature must verify
    //    over the JCS bytes of every field, so nothing inside the envelope
    //    (target origin, resource path, display name, expiry, the embedded
    //    session JWK) can have been altered after signing. What it does NOT
    //    buy is sender authenticity — bearer shares are self-asserted by
    //    design, and the UI must render the sender as "unverified" (never a
    //    checkmark). Policy/recipient-DID targets get a real expected
    //    signer in later stages (the delegation chain's issuer).
    // 7. Sender signature integrity is checked before any capability claim.
    let verified: boolean;
    try {
      verified = await verifyEnvelope(envelope, {
        expectedSignerDid: envelope.signature.signerDid,
      });
    } catch {
      verified = false;
    }
    if (!verified) return { state: "signature-invalid" };

    // 8. The link origin is part of the signed target binding. A valid
    // envelope copied to another canonical Share origin must not become a
    // valid link there, even when the caller did not provide an allowlist.
    if (envelope.target.origin !== linkOrigin) {
      return { state: "invalid-link", detail: "share origin does not match its signed target" };
    }

    // 9. Single-file slice: only an exact resource selector. Folder
    //    browsing (prefix + kv/list) is a later stage.
    if (envelope.target.resource.kind !== "exact") {
      return { state: "unsupported", reason: "prefix-resource", envelope };
    }

    // 10. Expiry — checked BEFORE the delegation binding so a dead share
    //    reports "expired", not a capability failure (create aligns the
    //    delegation exp to always cover the envelope expiry, so anything
    //    past the envelope expiry is dead on both clocks).
    const now = options.now?.() ?? Date.now();
    if (Date.parse(envelope.expiry) <= now) {
      return { state: "expired", envelope };
    }

    // 11. Effective-capability binding is shared with the canonical SDK
    //    compatibility export; the browser adapter does not implement its
    //    own token verifier.
    const capability = checkBearerDelegation(envelope, { now: () => now });
    if (!capability.ok) {
      return { state: "capability-invalid", detail: "signed delegation is not valid for this share" };
    }

    // 12. Content (stage 4, bearer slice): fetch + verify + decrypt the
    //     sealed content blob the SIGNED pointer names. Runs only after
    //     every check above passed. Direct registry fetch is the bearer
    //     semantics (possession of the link is the authority); later slices
    //     do a node capability-gated read here instead.
    if (envelope.content === undefined) {
      return { state: "ok", envelope, senderVerified: false };
    }
    let contentBlob: Uint8Array;
    try {
      contentBlob = await fetchBlob(options.registryBaseUrl, envelope.content.cid, {
        ...(options.fetchFn !== undefined ? { fetchFn: options.fetchFn } : {}),
      });
    } catch (error) {
      // A CID mismatch is an integrity failure (lying registry), not an
      // availability failure — surface it as such and render NOTHING.
      if (error instanceof CidMismatchError) {
        return { state: "content-integrity-failed" };
      }
      if (error instanceof RegistryHttpError) {
        return {
          state: "content-fetch-failed",
          detail: `registry returned ${error.status}`,
        };
      }
      return { state: "content-fetch-failed", detail: "shared content is unavailable" };
    }
    const contentKey = fromBase64Url(envelope.content.key); // schema-validated 32 bytes
    try {
      const contentBytes = await open(contentBlob, contentKey);
      let content: string | undefined;
      try {
        content = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(contentBytes);
      } catch {
        // Binary content is still safe to download. It must never be forced
        // through the Markdown/HTML renderer merely because the envelope's
        // legacy v1 shape has no MIME field.
      }
      return { state: "ok", envelope, senderVerified: false, contentBytes, ...(content === undefined ? {} : { content }) };
    } catch {
      return { state: "content-integrity-failed" };
    } finally {
      contentKey.fill(0);
    }
  } finally {
    // Memory-only key hygiene: the fragment key is dead after decryption.
    key32?.fill(0);
  }
}
