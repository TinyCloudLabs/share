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
 *   4. JSON.parse + strict schema parse    → v1 or recipient-DID v2 envelope
 *   5. switch on version/target kind       → recipient-DID v2 follows its
 *      signature/native/routing/account/node pipeline; v1 bearer behavior is
 *      unchanged and policy remains an honest unsupported state
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
 * The key-bearing href and fragment key are confined to the steps 1-3 decrypt
 * stage. Its inner `finally` zeroes the key before schema, native authority,
 * identity, or node work begins, on success and every error path alike. They
 * are never logged, stored, sent, or captured by a continuation; main.ts
 * scrubs location.hash/history synchronously before this pipeline runs.
 */
import {
  fromBase64Url,
  open,
  parseShareUrl,
  recipientDidEnvelopeV2Schema,
  shareEnvelopeSchema,
  verifyEnvelope,
  type ShareEnvelope,
  type RecipientDidEnvelopeV2,
} from "@tinycloud/share-envelope";
import {
  CidMismatchError,
  RegistryHttpError,
  fetchBlob,
} from "@tinycloud/share-registry";

import { checkBearerDelegation } from "./delegation.js";
import {
  continueRecipientDidShare,
  openRecipientDidShare,
  type RecipientAccountMode,
  type RecipientDidOpenResult,
  type RecipientDidViewerAdapter,
  type VerifiedRecipientDidContinuation,
} from "./recipient-did.js";

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
  | { state: "ok"; access: "bearer"; envelope: ShareEnvelope; senderVerified: false; content?: string }
  /** Verified recipient-DID share, read through the exact signed node. */
  | { state: "ok"; access: "recipient-did"; envelope: RecipientDidEnvelopeV2; senderVerified: true; content: string }
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
  /** Signed content pointer present, but the registry couldn't serve the blob. */
  | { state: "content-fetch-failed"; detail: string }
  /**
   * Signed content pointer present, but the fetched bytes failed
   * verification: CID mismatch, AEAD (wrong key / tampering), or
   * non-UTF-8 plaintext. Nothing may be rendered.
   */
  | { state: "content-integrity-failed" }
  /** This build has no native/OpenKey/node adapter; no identity provider was contacted. */
  | { state: "recipient-adapter-unavailable" }
  /** The v2 envelope or its complete authority chain failed local verification. */
  | { state: "recipient-verification-failed" }
  /** Verified share is waiting for an explicit, user-initiated account selection. */
  | {
      state: "recipient-identity-required";
      envelope: RecipientDidEnvelopeV2;
      continuation: VerifiedRecipientDidContinuation;
    }
  | {
      state: "recipient-wrong-account";
      envelope: RecipientDidEnvelopeV2;
      continuation: VerifiedRecipientDidContinuation;
    }
  | {
      state: "recipient-identity-cancelled";
      envelope: RecipientDidEnvelopeV2;
      continuation: VerifiedRecipientDidContinuation;
    }
  | { state: "recipient-node-unauthorized"; envelope: RecipientDidEnvelopeV2 }
  | { state: "recipient-node-not-found"; envelope: RecipientDidEnvelopeV2 }
  | { state: "recipient-node-unavailable"; envelope: RecipientDidEnvelopeV2 }
  | { state: "recipient-content-invalid"; envelope: RecipientDidEnvelopeV2 }
  | {
      state: "recipient-continuation-expired";
      envelope: RecipientDidEnvelopeV2;
    }
  | { state: "recipient-expired"; envelope: RecipientDidEnvelopeV2 }
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
  /** Recipient-DID SDK boundary. Omit to fail closed without identity I/O. */
  recipientDidAdapter?: RecipientDidViewerAdapter;
  /** Static deployment allowlist, generated into CSP by Vite. */
  allowedNodeOrigins?: readonly string[];
  /** `connect` is used only from the viewer's explicit account button. */
  recipientAccountMode?: RecipientAccountMode;
}

function recipientOpenResultToResolveResult(
  recipient: RecipientDidOpenResult,
): ResolveResult {
  switch (recipient.state) {
    case "recipient-ok":
      return {
        state: "ok",
        access: "recipient-did",
        envelope: recipient.envelope,
        senderVerified: true,
        content: recipient.content,
      };
    case "recipient-verification-failed":
      return { state: "recipient-verification-failed" };
    default:
      return recipient;
  }
}

/** Resume account selection from verified state without replaying the link. */
export async function continueRecipientDidResolution(
  continuation: VerifiedRecipientDidContinuation,
  options: {
    adapter: RecipientDidViewerAdapter;
    accountMode: RecipientAccountMode;
    now?: Date;
  },
): Promise<ResolveResult> {
  return recipientOpenResultToResolveResult(
    await continueRecipientDidShare(continuation, options),
  );
}

type DecryptedShareLinkResult =
  | { ok: true; plaintext: Uint8Array }
  | { ok: false; result: ResolveResult };

/**
 * The only stage allowed to retain the key-bearing href or parsed fragment
 * key. It returns plaintext only, and its inner finally zeroes the key before
 * schema, signature, native authority, identity, or node work can begin.
 */
async function decryptShareLink(
  href: string,
  options: ResolveShareOptions,
): Promise<DecryptedShareLinkResult> {
  // 1. Parse the link. The key comes from the FRAGMENT only; parseShareUrl
  //    already rejects query strings, userinfo, and non-canonical CIDs.
  let ciphertextCid: string;
  let key32: Uint8Array;
  try {
    ({ ciphertextCid, key32 } = parseShareUrl(href));
  } catch (error) {
    return {
      ok: false,
      result: { state: "invalid-link", detail: message(error) },
    };
  }
  try {
    options.onKeyParsed?.(key32);

    // 2. Fetch the sealed blob. fetchBlob re-verifies the CID of every
    //    received byte (trustless gateway posture) before returning.
    let blob: Uint8Array;
    try {
      blob = await fetchBlob(options.registryBaseUrl, ciphertextCid, {
        ...(options.fetchFn !== undefined ? { fetchFn: options.fetchFn } : {}),
      });
    } catch (error) {
      if (error instanceof CidMismatchError) {
        return { ok: false, result: { state: "cid-mismatch" } };
      }
      if (error instanceof RegistryHttpError) {
        return {
          ok: false,
          result: {
            state: "fetch-failed",
            detail: `registry returned ${error.status}`,
          },
        };
      }
      return {
        ok: false,
        result: { state: "fetch-failed", detail: message(error) },
      };
    }

    // 3. Decrypt. Any AEAD failure (wrong key, tampering that survived a
    //    correct CID — impossible from the network, but fail closed anyway)
    //    lands here.
    let plaintext: Uint8Array;
    try {
      plaintext = await open(blob, key32);
    } catch {
      return { ok: false, result: { state: "decrypt-failed" } };
    }
    return { ok: true, plaintext };
  } finally {
    key32.fill(0);
  }
}

/**
 * Non-async boundary: this frame releases its href argument after handing it
 * to the isolated decrypt stage. The continuation captures options only.
 */
export function resolveShare(
  href: string,
  options: ResolveShareOptions,
): Promise<ResolveResult> {
  return decryptShareLink(href, options).then((decrypted) =>
    decrypted.ok
      ? resolveDecryptedShare(decrypted.plaintext, options)
      : decrypted.result,
  );
}

async function resolveDecryptedShare(
  plaintext: Uint8Array,
  options: ResolveShareOptions,
): Promise<ResolveResult> {
  // 4. Bytes → JSON → strict schema. Unknown fields, missing fields, or
  //    malformed values are all rejected by the zod schema.
  let decoded: unknown;
  try {
    decoded = JSON.parse(
      new TextDecoder("utf-8", { fatal: true }).decode(plaintext),
    );
  } catch {
    return { state: "envelope-invalid" };
  }

  // Recipient-DID v2 gets its own strict schema and atomic native boundary.
  // The only network activity so far is the permitted registry fetch.
  if (
    typeof decoded === "object" && decoded !== null &&
    (decoded as { version?: unknown }).version === 2
  ) {
    if (!recipientDidEnvelopeV2Schema.safeParse(decoded).success) {
      return { state: "envelope-invalid" };
    }
    if (options.recipientDidAdapter === undefined) {
      return { state: "recipient-adapter-unavailable" };
    }
    const recipient = await openRecipientDidShare(decoded, {
      adapter: options.recipientDidAdapter,
      allowedOrigins: options.allowedNodeOrigins ?? [],
      accountMode: options.recipientAccountMode ?? "active",
      ...(options.now !== undefined ? { now: new Date(options.now()) } : {}),
    });
    return recipientOpenResultToResolveResult(recipient);
  }

  let envelope: ShareEnvelope;
  try {
    envelope = shareEnvelopeSchema.parse(decoded);
  } catch {
    return { state: "envelope-invalid" };
  }

  // 5. Mode detection: switch on the signed discriminated target FIRST
  //    (viewer spec §1). This stage implements only the bearer path; the
  //    others get an honest "unsupported" — we do NOT fake verification
  //    for them (there is no expected signer to verify against yet).
  if (envelope.authorizationTarget.kind === "policy") {
    return { state: "unsupported", reason: "policy-target", envelope };
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
  let verified: boolean;
  try {
    verified = await verifyEnvelope(envelope, {
      expectedSignerDid: envelope.signature.signerDid,
    });
  } catch {
    verified = false;
  }
  if (!verified) return { state: "signature-invalid" };

  // 7. Single-file slice: only an exact resource selector. Folder
  //    browsing (prefix + kv/list) is a later stage.
  if (envelope.target.resource.kind !== "exact") {
    return { state: "unsupported", reason: "prefix-resource", envelope };
  }

  // 8. Expiry — checked BEFORE the delegation binding so a dead share
  //    reports "expired", not a capability failure (create aligns the
  //    delegation exp to always cover the envelope expiry, so anything
  //    past the envelope expiry is dead on both clocks).
  const now = options.now?.() ?? Date.now();
  if (Date.parse(envelope.expiry) <= now) {
    return { state: "expired", envelope };
  }

  // 9. Effective-capability binding (viewer spec §1). The envelope
  //    signature only proves the envelope wasn't altered; it says nothing
  //    about whether the embedded delegation can authorize the embedded
  //    key. Decode AND verify the delegation (EdDSA signature against its
  //    own iss, required exp / optional nbf) and require (a) delegatee
  //    == the session key's did:key and (b) a read capability covering
  //    the signed target on canonical segment boundaries. Full CHAIN
  //    verification against owner roots stays the node's job at read time
  //    in later slices — see delegation.ts.
  const capability = checkBearerDelegation(envelope, { now: () => now });
  if (!capability.ok) {
    return { state: "capability-invalid", detail: capability.detail };
  }

  // 10. Content (stage 4, bearer slice): fetch + verify + decrypt the
  //     sealed content blob the SIGNED pointer names. Runs only after
  //     every check above passed. Direct registry fetch is the bearer
  //     semantics (possession of the link is the authority); later slices
  //     do a node capability-gated read here instead.
  if (envelope.content === undefined) {
    return { state: "ok", access: "bearer", envelope, senderVerified: false };
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
    return { state: "content-fetch-failed", detail: message(error) };
  }
  const contentKey = fromBase64Url(envelope.content.key); // schema-validated 32 bytes
  try {
    const contentBytes = await open(contentBlob, contentKey);
    const content = new TextDecoder("utf-8", { fatal: true }).decode(contentBytes);
    return {
      state: "ok",
      access: "bearer",
      envelope,
      senderVerified: false,
      content,
    };
  } catch {
    return { state: "content-integrity-failed" };
  } finally {
    contentKey.fill(0);
  }
}

function message(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
