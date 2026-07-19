import {
  canonicalDigest,
  createInvitationDraft,
  signedInvitationProof,
  type ContentSource,
  type SenderScope,
} from "./protocol.js";
import { mapTransportFailure, type ShareTransport, type TransportErrorCode } from "./transport.js";
import { assertTrustedNodeScope, verifyNodeProof } from "./node-verifier.js";
import { SIGNATURE_DOMAINS } from "./protocol.js";

export type SenderState =
  | { readonly state: "editing" }
  | { readonly state: "authorizing" }
  | { readonly state: "requesting" }
  | { readonly state: "requested"; readonly retryAfterSeconds: number; readonly shareId: string; readonly resource: string }
  | { readonly state: "delivery-failed"; readonly retryable: boolean; readonly code: TransportErrorCode }
  | { readonly state: "unavailable"; readonly code: TransportErrorCode }
  | { readonly state: "invalid"; readonly message: string };

export interface SenderController {
  readonly state: SenderState;
  subscribe(listener: (state: SenderState) => void): () => void;
  request(input: { readonly email: string; readonly source: ContentSource; readonly scope: SenderScope; readonly shareId: string; readonly expiresAt: string }): Promise<void>;
}

export function createSenderController(input: {
  readonly transport: ShareTransport;
  readonly uploadEnvelope: (cid: string, blob: Uint8Array) => Promise<void>;
}): SenderController {
  let state: SenderState = { state: "editing" };
  const listeners = new Set<(next: SenderState) => void>();
  const setState = (next: SenderState): void => { state = next; listeners.forEach((listener) => listener(next)); };
  return {
    get state() { return state; },
    subscribe(listener) { listeners.add(listener); return () => listeners.delete(listener); },
    async request(request) {
      try {
        setState({ state: "authorizing" });
        const draft = await createInvitationDraft({ ...request, uploadEnvelope: input.uploadEnvelope });
        const issuedAt = new Date().toISOString();
        const signed = await signedInvitationProof(draft, request.scope, issuedAt);
        const authorized = await input.transport.authorizeInvitation(signed.request);
        const trustedShare = {
          shareId: draft.envelope.shareId,
          shareCid: draft.shareCid,
          policyCid: draft.policyCid,
          recipientEmail: draft.email,
          recipientHint: draft.envelope.display.recipientHint ?? "",
          expiry: draft.envelope.expiry,
          nodeOrigin: request.scope.targetOrigin,
          nodeAudience: request.scope.nodeAudience,
          requestOrigin: "https://share.tinycloud.xyz",
          delegationCid: request.scope.delegationCid,
          authorityMaterialHandle: request.scope.authorityMaterialHandle,
          authorityMaterialDigest: request.scope.authorityMaterialDigest,
          contentSource: draft.source,
          contentSourceDigest: draft.sourceDigest,
          action: draft.source.action,
          resource: draft.source.path,
          trustedNode: request.scope.trustedNode,
        } as const;
        assertTrustedNodeScope(trustedShare, request.scope.trustedNode);
        await verifyNodeProof(authorized.authorization, authorized.proof, request.scope.trustedNode, SIGNATURE_DOMAINS.inviteAuthorization);
        const expected = { shareCid: draft.shareCid, shareId: draft.envelope.shareId, policyCid: draft.policyCid, delegationCid: request.scope.delegationCid, authorityMaterialHandle: request.scope.authorityMaterialHandle, authorityMaterialDigest: request.scope.authorityMaterialDigest, targetOrigin: request.scope.targetOrigin, nodeAudience: request.scope.nodeAudience, contentSource: draft.source, contentSourceDigest: draft.sourceDigest, recipientEmail: draft.email, documentName: request.scope.documentName, shareExpiresAt: draft.envelope.expiry } as const;
        for (const [key, value] of Object.entries(expected)) {
          const actual = (authorized.authorization as unknown as Record<string, unknown>)[key];
          if (typeof value === "object" ? JSON.stringify(actual) !== JSON.stringify(value) : actual !== value) throw new Error("invitation-authorization-mismatch");
        }
        setState({ state: "requesting" });
        const accepted = await input.transport.requestDelivery({
          ...authorized.authorization,
          proof: authorized.proof,
          shareUrl: draft.shareUrl,
        });
        setState({ state: "requested", retryAfterSeconds: accepted.retryAfterSeconds, shareId: draft.envelope.shareId, resource: request.source.path });
      } catch (error) {
        const failure = mapTransportFailure(error);
        setState({ state: failure.code === "capability-unavailable" ? "unavailable" : failure.code === "invalid" ? "invalid" : "delivery-failed", retryable: failure.retryable, code: failure.code, ...(failure.code === "invalid" ? { message: "Check the email and resource details, then try again." } : {}) } as SenderState);
      }
    },
  };
}

export async function requestBodyDigest(value: unknown): Promise<string> { return canonicalDigest(value); }
