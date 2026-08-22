import { receiveShare, ShareReceiveError, type ShareMetadata } from "@tinycloud/share-sdk";
import type { ShareEnvelope, ShareEnvelopeV3 } from "@tinycloud/share-envelope";

export type UnsupportedReason = "policy-target" | "prefix-resource";

export type ResolveResult =
  | { state: "ok"; access?: "bearer" | "policy"; envelope: ShareEnvelope | ShareEnvelopeV3; senderVerified: boolean; content?: string; contentBytes?: Uint8Array }
  | { state: "invalid-link"; detail: string }
  | { state: "fetch-failed"; detail: string }
  | { state: "cid-mismatch" }
  | { state: "envelope-invalid" }
  | { state: "signature-invalid" }
  | { state: "expired"; expiresAt: string }
  | { state: "policy-authorization-required"; envelope: ShareEnvelopeV3; shareCid: string }
  | { state: "content-integrity-failed" }
  | { state: "unsupported"; reason: UnsupportedReason };

export interface ResolveShareOptions {
  readonly expectedOrigin?: string;
  readonly now?: () => number;
}

/** Parse only the current public Policy/v3 invitation. */
export async function resolveShare(href: string, options: ResolveShareOptions = {}): Promise<ResolveResult> {
  let envelope: ShareEnvelopeV3 | undefined;
  let shareCid: string | undefined;
  try {
    await receiveShare(href, {
      expectedOrigin: options.expectedOrigin ?? "https://share.tinycloud.xyz",
      ...(options.now === undefined ? {} : { now: options.now }),
      onResolvedAddressedEnvelope: (value, cid) => { envelope = value; shareCid = cid; },
    });
    if (envelope !== undefined && shareCid !== undefined) return { state: "policy-authorization-required", envelope, shareCid };
    return { state: "unsupported", reason: "policy-target" };
  } catch (error) {
    if (error instanceof ShareReceiveError) return mapReceiveError(error);
    return { state: "fetch-failed", detail: "share unavailable" };
  }
}

/** Presentation-only envelope for content opened through native `tc1`. */
export function presentationEnvelope(
  metadata: ShareMetadata,
  content?: { readonly filename: string; readonly mediaType: string },
): ShareEnvelope {
  return {
    version: 1,
    shareId: metadata.shareId,
    delegation: "[redacted]",
    authorizationTarget: { kind: "bearerKey", sessionJwk: { kty: "OKP", crv: "Ed25519", x: "" } },
    target: { origin: metadata.target.origin, nodeAudience: metadata.target.nodeAudience, spaceId: metadata.target.spaceId, resource: metadata.resource },
    display: { ...metadata.display, ...(content === undefined ? {} : { filename: content.filename }) },
    expiry: metadata.expiresAt,
    signature: { signerDid: "did:key:z6Mkrender-only", algorithm: "Ed25519", value: "" },
    ...(content === undefined ? {} : { metadata: { filename: content.filename, mediaType: content.mediaType } }),
  } as unknown as ShareEnvelope;
}

function mapReceiveError(error: ShareReceiveError): ResolveResult {
  switch (error.code) {
    case "invalid-link": return { state: "invalid-link", detail: "share link format is invalid" };
    case "max-bytes-exceeded":
    case "content-integrity-failed": return { state: "content-integrity-failed" };
    case "cid-mismatch": return { state: "cid-mismatch" };
    case "envelope-invalid": return { state: "envelope-invalid" };
    case "origin-mismatch": return { state: "invalid-link", detail: "share origin does not match this deployment" };
    case "signature-invalid": return { state: "signature-invalid" };
    case "expired": return { state: "expired", expiresAt: error.details?.expiresAt ?? new Date().toISOString() };
    case "unsupported-target": return { state: "unsupported", reason: error.details?.reason === "prefix-resource" ? "prefix-resource" : "policy-target" };
    default: return { state: "fetch-failed", detail: "share unavailable" };
  }
}
