import {
  canonicalDigest,
  createInvitationDraft,
  signedInvitationProof,
  type ContentSource,
  type SenderScope,
} from "./protocol.js";
import { mapTransportFailure, type ShareTransport, type TransportErrorCode } from "./transport.js";

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
