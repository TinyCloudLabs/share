/**
 * Browser adapter for the canonical headless Share SDK.
 *
 * This module owns only browser presentation and the holder authorization
 * seam. Link parsing, fragment hygiene, envelope verification, policy trust,
 * content binding, and byte limits remain in @tinycloud/share-sdk.
 */
import {
  receiveShare,
  ShareReceiveError,
  createAddressedAuthorization,
  type ShareNodeTrust,
  type SharePresentationMaterial,
  type ShareMetadata,
  type ShareAuthorizationAdapter,
  type ShareAuthorizedContent,
  type SharePolicyAuthority,
} from "@tinycloud/share-sdk";
import type { SharePolicyChallenge as PolicyChallenge, SharePresentationMaterial as PolicyPresentationMaterial } from "@tinycloud/share-sdk";
import { nativePayload } from "./policy-v2.js";
import { verifyNodeProof } from "../email-share/node-verifier.js";
import { type TrustedNode } from "../email-share/protocol.js";
import type { ShareEnvelope, ShareEnvelopeV2 } from "@tinycloud/share-envelope";

export type UnsupportedReason = "policy-target" | "recipient-did-target" | "prefix-resource";

export type ResolveResult =
  | { state: "ok"; access?: "bearer" | "policy"; envelope: ShareEnvelope; senderVerified: boolean; content?: string; contentBytes?: Uint8Array }
  | { state: "invalid-link"; detail: string }
  | { state: "fetch-failed"; detail: string }
  | { state: "cid-mismatch" }
  | { state: "decrypt-failed" }
  | { state: "envelope-invalid" }
  | { state: "signature-invalid" }
  | { state: "capability-invalid"; detail: string }
  | { state: "expired"; expiresAt: string }
  /** Retained for the legacy invitation controller; canonical resolution never creates this state. */
  | { state: "policy-email-claim-required"; envelope: ShareEnvelope; shareCid: string; policy: Record<string, unknown> }
  | { state: "policy-v2-claim-required"; envelope: ShareEnvelopeV2; shareCid: string; policy: Record<string, unknown> }
  | { state: "recipient-did-authorization-required"; envelope: ShareEnvelopeV2; shareCid: string }
  | { state: "content-fetch-failed"; detail: string }
  | { state: "content-integrity-failed" }
  | { state: "unsupported"; reason: UnsupportedReason };

export interface ResolveShareOptions {
  readonly registryBaseUrl: string;
  readonly expectedOrigin?: string;
  readonly fetchFn?: typeof globalThis.fetch;
  readonly now?: () => number;
  readonly onKeyParsed?: (key32: Uint8Array) => void;
  readonly trustedPolicyAuthority?: SharePolicyAuthority;
  readonly authorization?: ShareAuthorizationAdapter<ShareAuthorizedContent>;
  readonly authorizationResumeToken?: string;
  readonly authorizationProof?: unknown;
}

export interface BrowserAddressedAuthorizationOptions {
  readonly nodeOrigin: string;
  readonly trustedNode: TrustedNode;
  readonly holderDid: string;
  readonly buildPresentation: (input: { readonly challenge: PolicyChallenge; readonly envelope: ShareEnvelopeV2; readonly policy: Record<string, unknown> }) => Promise<PolicyPresentationMaterial | Record<string, unknown>>;
  readonly fetchFn?: typeof fetch;
}

/**
 * The holder ceremony is injected into the SDK's authorization interface.
 * The client below is a transport adapter; it does not parse share links or
 * perform a second envelope/content verification pipeline.
 */
export function createBrowserAddressedAuthorization(input: BrowserAddressedAuthorizationOptions): ShareAuthorizationAdapter<ShareAuthorizedContent> {
  const trust: ShareNodeTrust = { invitationKid: input.trustedNode.invitationKid, invitationPublicKey: input.trustedNode.invitationPublicKey };
  return createAddressedAuthorization({
    nodeOrigin: input.nodeOrigin,
    trustedNode: trust,
    holderDid: input.holderDid,
    ...(input.fetchFn === undefined ? {} : { fetchFn: input.fetchFn }),
    buildPresentation: async ({ challenge, envelope, policy }): Promise<SharePresentationMaterial> => input.buildPresentation({ challenge: challenge as PolicyChallenge, envelope, policy }) as Promise<SharePresentationMaterial>,
  });
}

export async function resolveShare(href: string, options: ResolveShareOptions): Promise<ResolveResult> {
  let addressedEnvelope: ShareEnvelope | ShareEnvelopeV2 | undefined;
  let addressedCid: string | undefined;
  try {
    const received = await receiveShare(href, {
      registryBaseUrl: options.registryBaseUrl,
      expectedOrigin: options.expectedOrigin ?? "https://share.tinycloud.xyz",
      ...(options.fetchFn === undefined ? {} : { fetchFn: options.fetchFn }),
      ...(options.now === undefined ? {} : { now: options.now }),
      ...(options.onKeyParsed === undefined ? {} : { onKeyParsed: options.onKeyParsed }),
      ...(options.trustedPolicyAuthority === undefined ? {} : { trustedPolicyAuthority: options.trustedPolicyAuthority }),
      ...(options.authorization === undefined ? {} : { authorization: options.authorization }),
      ...(options.authorizationResumeToken === undefined ? {} : { authorizationResumeToken: options.authorizationResumeToken }),
      ...(options.authorizationProof === undefined ? {} : { authorizationProof: options.authorizationProof }),
      onResolvedAddressedEnvelope: (envelope, cid) => { addressedEnvelope = envelope; addressedCid = cid; },
    });
    if ("state" in received) {
      if (addressedEnvelope?.version === 2 && addressedCid !== undefined) {
        return addressedEnvelope.recipientMatcher.kind === "recipientDid"
          ? { state: "recipient-did-authorization-required", envelope: addressedEnvelope, shareCid: addressedCid }
          : { state: "policy-v2-claim-required", envelope: addressedEnvelope, shareCid: addressedCid, policy: {} };
      }
      return { state: "unsupported", reason: "policy-target" };
    }
    const envelope = presentationEnvelope(received.metadata);
    const addressed = received.metadata.target.kind !== "bearer";
    return {
      state: "ok",
      ...(addressed ? { access: "policy" as const } : { access: "bearer" as const }),
      envelope,
      senderVerified: false,
      ...(received.text === undefined ? {} : { content: received.text }),
      ...(received.metadata.content === undefined ? {} : { contentBytes: received.bytes }),
    };
  } catch (error) {
    if (error instanceof ShareReceiveError) {
      if (addressedEnvelope?.version === 2 && addressedCid !== undefined && error.code === "authorization-denied") {
        return addressedEnvelope.recipientMatcher.kind === "recipientDid"
          ? { state: "recipient-did-authorization-required", envelope: addressedEnvelope, shareCid: addressedCid }
          : { state: "policy-v2-claim-required", envelope: addressedEnvelope, shareCid: addressedCid, policy: {} };
      }
      return mapReceiveError(error);
    }
    return { state: "fetch-failed", detail: "share unavailable" };
  }
}

function presentationEnvelope(metadata: ShareMetadata): ShareEnvelope {
  return {
    version: 1,
    shareId: metadata.shareId,
    delegation: "[redacted]",
    authorizationTarget: { kind: "bearerKey", sessionJwk: { kty: "OKP", crv: "Ed25519", x: "" } },
    target: { origin: metadata.target.origin, nodeAudience: metadata.target.nodeAudience, spaceId: metadata.target.spaceId, resource: metadata.resource },
    display: metadata.display,
    expiry: metadata.expiresAt,
    signature: { signerDid: "did:key:z6Mkrender-only", algorithm: "Ed25519", value: "" },
  } as unknown as ShareEnvelope;
}

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
    case "expired": return { state: "expired", expiresAt: error.details?.expiresAt ?? new Date().toISOString() };
    case "content-integrity-failed": return { state: "content-integrity-failed" };
    case "unsupported-target": return { state: "unsupported", reason: error.details?.reason === "prefix-resource" ? "prefix-resource" : error.details?.reason === "recipient-did-target" ? "recipient-did-target" : "policy-target" };
    default: return { state: "fetch-failed", detail: "share unavailable" };
  }
}
