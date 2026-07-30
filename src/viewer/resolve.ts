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
  type ShareMetadata,
  type ShareAuthorizationAdapter,
  type ShareAuthorizedContent,
  type SharePolicyAuthority,
} from "@tinycloud/share-sdk";
import { ShareRecipientClient, type PolicyChallenge, type PolicyPresentationMaterial } from "@tinycloud/share-app-compat";
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
  | { state: "expired"; envelope: ShareEnvelope }
  /** Retained for the legacy invitation controller; canonical resolution never creates this state. */
  | { state: "policy-email-claim-required"; envelope: ShareEnvelope; shareCid: string; policy: Record<string, unknown> }
  | { state: "policy-v2-claim-required"; envelope: ShareEnvelopeV2; shareCid: string; policy: Record<string, unknown> }
  | { state: "recipient-did-authorization-required"; envelope: ShareEnvelopeV2; shareCid: string }
  | { state: "content-fetch-failed"; detail: string }
  | { state: "content-integrity-failed" }
  | { state: "unsupported"; reason: UnsupportedReason; envelope: ShareEnvelope };

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
  const clients = new WeakMap<object, ShareRecipientClient>();
  const clientFor = (envelope: ShareEnvelopeV2): ShareRecipientClient => {
    const existing = clients.get(envelope as unknown as object);
    if (existing !== undefined) return existing;
    const client = new ShareRecipientClient({
      nodeOrigin: input.nodeOrigin,
      trustedNode: input.trustedNode,
      holderDid: input.holderDid,
      envelope,
      shareCid: "",
      buildPresentation: input.buildPresentation,
      ...(input.fetchFn === undefined ? {} : { fetchFn: input.fetchFn }),
    });
    clients.set(envelope as unknown as object, client);
    return client;
  };
  const ready = async (envelope: ShareEnvelopeV2): Promise<ShareAuthorizedContent> => {
    const client = clientFor(envelope);
    await client.establishPolicySession();
    const response = await client.nativeInvoke({ action: "get", resource: envelope.resource });
    if (!response.ok) throw new Error("recipient read was rejected");
    const payload = await nativePayload(response, "get", envelope.resource.path);
    if (payload.bytes === undefined || payload.proof === undefined) throw new Error("recipient read proof is missing");
    return {
      bytes: payload.bytes,
      bodyDigest: String(payload.value.bodyDigest),
      contentSourceDigest: envelope.contentSourceDigest,
      binding: {
        shareId: envelope.shareId,
        delegationCid: envelope.delegationCid,
        authorityMaterialHandle: envelope.authorityMaterialHandle,
        authorityMaterialDigest: envelope.authorityMaterialDigest,
        resource: envelope.resource,
        ...(typeof payload.value.action === "string" ? { action: payload.value.action } : {}),
      },
      proof: { detached: payload.proof, response: payload.value },
    };
  };
  return {
    async begin({ envelope }) { return { state: "ready", value: await ready(envelope) }; },
    async resume({ envelope }) { return { state: "ready", value: await ready(envelope) }; },
    async verifyResult({ value, proof }) {
      try {
        if (typeof proof !== "object" || proof === null || Array.isArray(proof)) return false;
        const wrapper = proof as Record<string, unknown>;
        if (typeof wrapper.detached !== "object" || wrapper.detached === null || typeof wrapper.response !== "object" || wrapper.response === null || Array.isArray(wrapper.response)) return false;
        const response = { ...(wrapper.response as Record<string, unknown>) };
        delete response.proof;
        await verifyNodeProof(response, wrapper.detached as never, input.trustedNode, "xyz.tinycloud.share/read-response/v2\0");
        return typeof (wrapper.response as Record<string, unknown>).content === "string"
          && value.bodyDigest === (wrapper.response as Record<string, unknown>).bodyDigest;
      } catch { return false; }
    },
  };
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
        return { state: "policy-v2-claim-required", envelope: addressedEnvelope, shareCid: addressedCid, policy: {} };
      }
      return { state: "unsupported", reason: "policy-target", envelope: presentationEnvelope(fallbackMetadata(new Date().toISOString())) };
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
      if (addressedEnvelope?.version === 2 && addressedCid !== undefined && error.code === "authorization-denied") return { state: "policy-v2-claim-required", envelope: addressedEnvelope, shareCid: addressedCid, policy: {} };
      return mapReceiveError(error);
    }
    return { state: "fetch-failed", detail: "share unavailable" };
  }
}

function presentationEnvelope(metadata: ShareMetadata, expiry = metadata.expiresAt): ShareEnvelope {
  return {
    version: 1,
    shareId: metadata.shareId,
    delegation: "[redacted]",
    authorizationTarget: { kind: "bearerKey", sessionJwk: { kty: "OKP", crv: "Ed25519", x: "" } },
    target: { origin: metadata.target.origin, nodeAudience: metadata.target.nodeAudience, spaceId: metadata.target.spaceId, resource: metadata.resource },
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
  target: { kind: "bearer", origin: "https://share.tinycloud.xyz", nodeAudience: "unknown", spaceId: "unknown" },
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
    case "unsupported-target": return { state: "unsupported", reason: error.details?.reason === "prefix-resource" ? "prefix-resource" : error.details?.reason === "recipient-did-target" ? "recipient-did-target" : "policy-target", envelope: presentationEnvelope(fallbackMetadata(new Date().toISOString())) };
    default: return { state: "fetch-failed", detail: "share unavailable" };
  }
}
