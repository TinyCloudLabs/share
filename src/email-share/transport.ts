import type {
  AuthorizedInvitation,
  ContentSource,
  InvitationAuthorization,
  SignedProof,
} from "./protocol.js";

export type TransportErrorCode =
  | "offline"
  | "capability-unavailable"
  | "invalid"
  | "denied"
  | "expired"
  | "used"
  | "revoked"
  | "delivery-failed"
  | "unknown";

export class ShareTransportError extends Error {
  readonly code: TransportErrorCode;
  readonly retryable: boolean;

  constructor(code: TransportErrorCode, retryable = false) {
    super(code);
    this.name = "ShareTransportError";
    this.code = code;
    this.retryable = retryable;
  }
}

export interface ShareTransport {
  authorizeInvitation(input: Record<string, unknown>): Promise<AuthorizedInvitation>;
  requestDelivery(input: Record<string, unknown>): Promise<{ readonly status: "accepted"; readonly retryAfterSeconds: number; readonly delegationCid: string; readonly authorityMaterialHandle: string; readonly authorityMaterialDigest: string }>;
  resend(input: { readonly invitationId: string; readonly claimSecret: string }): Promise<{ readonly status: "accepted"; readonly retryAfterSeconds: number; readonly delegationCid: string; readonly authorityMaterialHandle: string; readonly authorityMaterialDigest: string }>;
  claimChallenge(input: { readonly invitationId: string; readonly method: "magic" | "otp"; readonly claimSecret?: string; readonly otp?: string }): Promise<ClaimChallengeResponse>;
  claimRedeem(input: Record<string, unknown>): Promise<ClaimCredentialResponse>;
  policyChallenge(input: Record<string, unknown>): Promise<{ readonly challenge: Record<string, unknown>; readonly proof: SignedProof }>;
  policySession(input: Record<string, unknown>): Promise<Record<string, unknown>>;
  read(input: Record<string, unknown>): Promise<{ readonly mediaType: "text/markdown; charset=utf-8"; readonly content: string; readonly contentSourceDigest: string; readonly bodyDigest: string; readonly delegationCid: string; readonly authorityMaterialHandle: string; readonly authorityMaterialDigest: string }>;
}

export interface ClaimChallengeResponse {
  readonly claimNonce: string;
  readonly shareCid: string;
  readonly shareId: string;
  readonly policyCid: string;
  readonly delegationCid: string;
  readonly authorityMaterialHandle: string;
  readonly authorityMaterialDigest: string;
  readonly contentSource: ContentSource;
  readonly contentSourceDigest: string;
  readonly emailHash: string;
  readonly targetOrigin: string;
  readonly nodeAudience: string;
  readonly expiresAt: string;
}

export interface ClaimCredentialResponse {
  readonly format: "vc+sd-jwt";
  readonly credential: string;
  readonly holderDid: string;
  readonly expiresAt: string;
}

function codeFor(status: number): TransportErrorCode {
  if (status === 401 || status === 403) return "denied";
  if (status === 404) return "used";
  if (status === 409) return "used";
  if (status === 410) return "expired";
  if (status === 429) return "delivery-failed";
  if (status === 503) return "capability-unavailable";
  return "unknown";
}

async function jsonRequest<T>(fetchFn: typeof fetch, origin: string, path: string, init: RequestInit): Promise<T> {
  let response: Response;
  try {
    response = await fetchFn(`${origin}${path}`, {
      ...init,
      credentials: "omit",
      redirect: "error",
      referrerPolicy: "no-referrer",
      cache: "no-store",
      headers: { accept: "application/json", "content-type": "application/json", ...init.headers },
    });
  } catch {
    throw new ShareTransportError("offline", true);
  }
  if (!response.ok) throw new ShareTransportError(codeFor(response.status), response.status >= 500 || response.status === 429);
  try {
    const body = await response.text();
    if (new TextEncoder().encode(body).length > 1_048_576) throw new Error("response-too-large");
    return JSON.parse(body) as T;
  } catch {
    throw new ShareTransportError("unknown", false);
  }
}

function record(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new ShareTransportError("unknown");
  return value as Record<string, unknown>;
}

function text(value: unknown): string { if (typeof value !== "string" || value.length === 0) throw new ShareTransportError("unknown"); return value; }

function exact(value: unknown, required: readonly string[], optional: readonly string[] = []): Record<string, unknown> {
  const object = record(value); const allowed = new Set([...required, ...optional]);
  if (required.some((key) => !(key in object)) || Object.keys(object).some((key) => !allowed.has(key))) throw new ShareTransportError("unknown");
  return object;
}

function parseAccepted(value: unknown): { readonly status: "accepted"; readonly retryAfterSeconds: number; readonly delegationCid: string; readonly authorityMaterialHandle: string; readonly authorityMaterialDigest: string } {
  const object = exact(value, ["status", "retryAfterSeconds", "delegationCid", "authorityMaterialHandle", "authorityMaterialDigest"]);
  if (object.status !== "accepted" || object.retryAfterSeconds !== 20) throw new ShareTransportError("unknown");
  return { status: "accepted", retryAfterSeconds: 20, delegationCid: text(object.delegationCid), authorityMaterialHandle: text(object.authorityMaterialHandle), authorityMaterialDigest: text(object.authorityMaterialDigest) };
}

function parseClaimChallenge(value: unknown): ClaimChallengeResponse {
  const object = exact(value, ["claimNonce", "shareCid", "shareId", "policyCid", "delegationCid", "authorityMaterialHandle", "authorityMaterialDigest", "contentSource", "contentSourceDigest", "emailHash", "targetOrigin", "nodeAudience", "expiresAt"]);
  for (const key of ["claimNonce", "shareCid", "shareId", "policyCid", "delegationCid", "authorityMaterialHandle", "authorityMaterialDigest", "contentSourceDigest", "emailHash", "targetOrigin", "nodeAudience", "expiresAt"]) text(object[key]);
  if (typeof object.contentSource !== "object" || object.contentSource === null) throw new ShareTransportError("unknown");
  return object as unknown as ClaimChallengeResponse;
}

function parseCredential(value: unknown): ClaimCredentialResponse {
  const object = exact(value, ["format", "credential", "holderDid", "expiresAt"]);
  if (object.format !== "vc+sd-jwt") throw new ShareTransportError("unknown");
  text(object.credential); text(object.holderDid); text(object.expiresAt);
  return object as unknown as ClaimCredentialResponse;
}

function parseRead(value: unknown): { readonly mediaType: "text/markdown; charset=utf-8"; readonly content: string; readonly contentSourceDigest: string; readonly bodyDigest: string; readonly delegationCid: string; readonly authorityMaterialHandle: string; readonly authorityMaterialDigest: string } {
  const object = exact(value, ["mediaType", "content", "contentSourceDigest", "bodyDigest", "delegationCid", "authorityMaterialHandle", "authorityMaterialDigest"]);
  if (object.mediaType !== "text/markdown; charset=utf-8" || typeof object.content !== "string" || new TextEncoder().encode(object.content).length > 1_048_576) throw new ShareTransportError("unknown");
  for (const key of ["contentSourceDigest", "bodyDigest", "delegationCid", "authorityMaterialHandle", "authorityMaterialDigest"]) text(object[key]);
  return object as never;
}

export function createHttpTransport(input: { readonly nodeOrigin: string; readonly credentialsOrigin: string; readonly fetchFn?: typeof fetch }): ShareTransport {
  for (const origin of [input.nodeOrigin, input.credentialsOrigin]) {
    const parsed = new URL(origin);
    if (parsed.protocol !== "https:" || parsed.origin !== origin) throw new TypeError("Trusted service origins must be canonical HTTPS origins.");
  }
  const fetchFn = input.fetchFn ?? globalThis.fetch.bind(globalThis);
  const postNode = <T>(path: string, body: Record<string, unknown>) => jsonRequest<T>(fetchFn, input.nodeOrigin, path, { method: "POST", body: JSON.stringify(body) });
  const postCredentials = <T>(path: string, body: Record<string, unknown>) => jsonRequest<T>(fetchFn, input.credentialsOrigin, path, { method: "POST", body: JSON.stringify(body) });
  return {
    authorizeInvitation: (body) => postNode<AuthorizedInvitation>("/share/v1/invitations/authorize", body),
    requestDelivery: async (body) => parseAccepted(await postCredentials("/v1/share-email/invitations", body)),
    resend: async (body) => parseAccepted(await postCredentials("/v1/share-email/invitations/resend", body)),
    claimChallenge: async (body) => parseClaimChallenge(await postCredentials("/v1/share-email/claims/challenge", body)),
    claimRedeem: async (body) => parseCredential(await postCredentials("/v1/share-email/claims/redeem", body)),
    policyChallenge: (body) => postNode("/share/v1/policy/challenges", body),
    policySession: (body) => postNode("/share/v1/policy/session", body),
    read: async (body) => parseRead(await postNode("/share/v1/read", body)),
  };
}

export function mapTransportFailure(error: unknown): ShareTransportError {
  return error instanceof ShareTransportError ? error : new ShareTransportError("unknown", false);
}
