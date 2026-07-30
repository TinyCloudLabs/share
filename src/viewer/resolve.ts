/**
 * Browser orchestration for addressed policy links. Bearer links are handled
 * by the compiled Share SDK below; this module retains only policy claim
 * state needed by the existing recipient UI.
 *
 * The bearer resolver owns fragment hygiene and verification. This adapter
 * never parses or decrypts bearer links itself.
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
  receiveShare,
  ShareReceiveError,
  type ShareMetadata,
} from "@tinycloud/share-sdk";
import { CidMismatchError, RegistryHttpError, fetchBlob } from "@tinycloud/share-registry";
import { parseAddressedEnvelope } from "@tinycloud/share-sdk";

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
  /** Trusted Share host; links from another origin are rejected before fetch. */
  expectedOrigin?: string;
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

async function resolveAddressedShare(
  href: string,
  options: ResolveShareOptions,
): Promise<ResolveResult> {
  // 1. Parse the link. The key comes from the FRAGMENT only; parseShareUrl
  //    already rejects query strings, userinfo, and non-canonical CIDs.
  let ciphertextCid: string;
  let key32: Uint8Array | undefined;
  let inlineBlob: Uint8Array | undefined;
  try {
    const parsed = parseCompactOrInlineShareUrl(href);
    ciphertextCid = parsed.ciphertextCid;
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

    // Addressed policy orchestration starts only after the SDK has declined
    // this non-bearer target; no bearer verification is performed here.
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

    return { state: "unsupported", reason: envelope.target.resource.kind === "prefix" ? "prefix-resource" : "policy-target", envelope };
  } finally {
    // Memory-only key hygiene: the fragment key is dead after decryption.
    key32?.fill(0);
  }
}

/**
 * Resolve bearer links through the compiled headless SDK used by tc. The
 * browser keeps only a redacted presentation envelope for rendering; keys,
 * delegation material, and content pointers never cross this adapter.
 * Addressed links continue through the policy claim orchestration below.
 */
export async function resolveShare(
  href: string,
  options: ResolveShareOptions,
): Promise<ResolveResult> {
  try {
    const received = await receiveShare(href, {
      registryBaseUrl: options.registryBaseUrl,
      expectedOrigin: options.expectedOrigin ?? "https://share.tinycloud.xyz",
      ...(options.fetchFn === undefined ? {} : { fetchFn: options.fetchFn }),
      ...(options.now === undefined ? {} : { now: options.now }),
      ...(options.onKeyParsed === undefined ? {} : { onKeyParsed: options.onKeyParsed }),
    });
    if ("state" in received) return resolveAddressedShare(href, options);
    const envelope = presentationEnvelope(received.metadata);
    return {
      state: "ok",
      access: "bearer",
      envelope,
      senderVerified: false,
      ...(received.text === undefined ? {} : { content: received.text }),
      ...(received.metadata.content === undefined ? {} : { contentBytes: received.bytes }),
    };
  } catch (error) {
    if (error instanceof ShareReceiveError && error.code !== "unsupported-target") return mapReceiveError(error);
  }
  return resolveAddressedShare(href, options);
}

function presentationEnvelope(metadata: ShareMetadata, expiry = metadata.expiresAt): ShareEnvelope {
  // This is intentionally a non-verifying presentation shape. The SDK has
  // already verified the real envelope and content before this projection.
  return {
    version: 1,
    shareId: metadata.shareId,
    delegation: "[redacted]",
    authorizationTarget: {
      kind: "bearerKey",
      sessionJwk: { kty: "OKP", crv: "Ed25519", x: "" },
    },
    target: {
      origin: metadata.target.origin,
      nodeAudience: metadata.target.nodeAudience,
      spaceId: metadata.target.spaceId,
      resource: metadata.resource,
    },
    display: metadata.display,
    expiry,
    signature: { signerDid: "did:key:z6Mkrender-only", algorithm: "Ed25519", value: "" },
  } as unknown as ShareEnvelope;
}

const fallbackMetadata = (expiresAt: string): ShareMetadata => ({
  protocol: "tinycloud-share",
  version: 1,
  shareId: "unknown",
  origin: "https://share.tinycloud.xyz",
  target: {
    kind: "bearer",
    origin: "https://share.tinycloud.xyz",
    nodeAudience: "unknown",
    spaceId: "unknown",
  },
  resource: { kind: "exact", path: "unknown" },
  actions: ["read"],
  expiresAt,
  display: {},
});

function mapReceiveError(error: ShareReceiveError): ResolveResult {
  switch (error.code) {
    case "invalid-link": return { state: "invalid-link", detail: "share link format is invalid" };
    case "fetch-failed": return error.details?.stage === "content" ? { state: "content-fetch-failed", detail: "shared content is unavailable" } : { state: "fetch-failed", detail: "registry unavailable" };
    case "max-bytes-exceeded": return { state: "content-integrity-failed" };
    case "cid-mismatch": return { state: "cid-mismatch" };
    case "decrypt-failed": return { state: "decrypt-failed" };
    case "envelope-invalid": return { state: "envelope-invalid" };
    case "origin-mismatch": return { state: "invalid-link", detail: "share origin does not match its signed target" };
    case "signature-invalid": return { state: "signature-invalid" };
    case "capability-invalid": return { state: "capability-invalid", detail: "signed delegation is not valid for this share" };
    case "expired": return { state: "expired", envelope: presentationEnvelope(fallbackMetadata(error.details?.expiresAt ?? new Date().toISOString()), error.details?.expiresAt) };
    case "content-integrity-failed": return { state: "content-integrity-failed" };
    case "unsupported-target": return { state: "unsupported", reason: "recipient-did-target", envelope: presentationEnvelope(fallbackMetadata(new Date().toISOString())) };
    default: return { state: "fetch-failed", detail: "share unavailable" };
  }
}
