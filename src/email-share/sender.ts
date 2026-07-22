import { canonicalDigest, type AuthoritativePolicyMaterial, type ContentSource, type SenderScope } from "./protocol.js";
import { createShareLink, sendShareEmail, type ShareArtifact, type ShareLinkPolicy } from "@tinycloud/share-sdk";
import { mapTransportFailure, type ShareTransport, type TransportErrorCode } from "./transport.js";

export type SenderPolicy = ShareLinkPolicy & AuthoritativePolicyMaterial;

export type SenderState =
  | { readonly state: "editing" }
  | { readonly state: "authorizing" }
  | { readonly state: "requesting" }
  | { readonly state: "requested"; readonly retryAfterSeconds: number; readonly shareId: string; readonly resource: string; readonly shareUrl: string }
  | { readonly state: "delivery-failed"; readonly retryable: boolean; readonly code: TransportErrorCode }
  | { readonly state: "unavailable"; readonly code: TransportErrorCode }
  | { readonly state: "invalid"; readonly message: string };

export interface SenderController {
  readonly state: SenderState;
  subscribe(listener: (state: SenderState) => void): () => void;
  request(input: { readonly email: string; readonly source: ContentSource; readonly scope: SenderScope; readonly shareId: string; readonly expiresAt: string; readonly policy: SenderPolicy }): Promise<void>;
}

export function createSenderController(input: {
  readonly transport: ShareTransport;
  readonly uploadEnvelope: (cid: string, blob: Uint8Array, deleteAfter: string) => Promise<void>;
  readonly publishBinding?: (binding: Record<string, unknown>) => Promise<void>;
}): SenderController {
  let state: SenderState = { state: "editing" };
  let inFlight = false;
  const listeners = new Set<(next: SenderState) => void>();
  const setState = (next: SenderState): void => { state = next; listeners.forEach((listener) => listener(next)); };
  return {
    get state() { return state; },
    subscribe(listener) { listeners.add(listener); return () => listeners.delete(listener); },
    async request(request) {
      if (inFlight) return;
      inFlight = true;
      try {
        setState({ state: "authorizing" });
        const share: ShareArtifact = await createShareLink({
          email: request.email,
          source: request.source,
          scope: request.scope,
          policy: request.policy,
          shareId: request.shareId,
          expiresAt: request.expiresAt,
          adapters: { uploadEnvelope: input.uploadEnvelope, ...(input.publishBinding === undefined ? {} : { publishBinding: input.publishBinding }) },
        });
        setState({ state: "requesting" });
        const accepted = await sendShareEmail({ share, scope: request.scope, adapters: input.transport });
        setState({ state: "requested", retryAfterSeconds: accepted.retryAfterSeconds, shareId: share.shareId, resource: request.source.path, shareUrl: share.shareUrl });
      } catch (error) {
        const failure = mapTransportFailure(error);
        const code = error instanceof TypeError ? "invalid" : failure.code;
        setState({ state: code === "capability-unavailable" ? "unavailable" : code === "invalid" ? "invalid" : "delivery-failed", retryable: code === "invalid" ? false : failure.retryable, code, ...(code === "invalid" ? { message: "Check the email and resource details, then try again." } : {}) } as SenderState);
      } finally {
        inFlight = false;
      }
    },
  };
}

export async function requestBodyDigest(value: unknown): Promise<string> { return canonicalDigest(value); }
