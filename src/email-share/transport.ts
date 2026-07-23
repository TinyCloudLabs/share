import type {
  AuthorizedInvitation,
  ContentSource,
  InvitationAuthorization,
  SignedProof,
} from "./protocol.js";
import { validateSource } from "./protocol.js";

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
  readonly retryAfterSeconds?: number;

  constructor(code: TransportErrorCode, retryable = false, retryAfterSeconds?: number) {
    super(code);
    this.name = "ShareTransportError";
    this.code = code;
    this.retryable = retryable;
    if (retryAfterSeconds !== undefined) this.retryAfterSeconds = retryAfterSeconds;
  }
}

export interface ShareTransport {
  authorizeInvitation(input: Record<string, unknown>): Promise<AuthorizedInvitation>;
  requestDelivery(input: Record<string, unknown>): Promise<{ readonly status: "accepted"; readonly retryAfterSeconds: number; readonly delegationCid: string; readonly authorityMaterialHandle: string; readonly authorityMaterialDigest: string }>;
  resend(input: { readonly invitationId: string; readonly claimSecret: string }): Promise<{ readonly status: "accepted"; readonly retryAfterSeconds: number; readonly delegationCid: string; readonly authorityMaterialHandle: string; readonly authorityMaterialDigest: string }>;
  activate(input: { readonly invitationId: string; readonly claimSecret: string }): Promise<{ readonly status: "accepted"; readonly retryAfterSeconds: number; readonly activationId: string }>;
  claimChallenge(input: { readonly invitationId: string; readonly method: "magic" | "otp"; readonly activationId?: string; readonly otp?: string }): Promise<ClaimChallengeResponse>;
  claimRedeem(input: Record<string, unknown>): Promise<ClaimCredentialResponse>;
  policyChallenge(input: Record<string, unknown>): Promise<{ readonly challenge: Record<string, unknown>; readonly proof: SignedProof }>;
  policySession(input: Record<string, unknown>): Promise<{ readonly session: Record<string, unknown>; readonly proof: SignedProof }>;
  read(input: Record<string, unknown>): Promise<ReadResponse>;
}

export interface ReadResponse {
  readonly type: "TinyCloudShareReadResponse";
  readonly version: 1;
  readonly sessionId: string;
  readonly requestJti: string;
  readonly readJti: string;
  readonly audience: string;
  readonly holderDid: string;
  readonly credentialDigest: string;
  readonly issuedAt: string;
  readonly expiresAt: string;
  readonly mediaType: "text/markdown; charset=utf-8";
  readonly content: string;
  readonly contentSource: ContentSource;
  readonly contentSourceDigest: string;
  readonly action: "tinycloud.kv/get" | "tinycloud.sql/read";
  readonly resource: string;
  readonly requestBodyDigest: string;
  readonly bodyDigest: string;
  readonly delegationCid: string;
  readonly authorityMaterialHandle: string;
  readonly authorityMaterialDigest: string;
  readonly proof: SignedProof;
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

function retryAfter(value: string | null): number | undefined {
  if (value === null) return undefined;
  const seconds = Number(value);
  return Number.isInteger(seconds) && seconds >= 0 && seconds <= 3600 ? seconds : undefined;
}

function parseFailure(value: unknown): TransportErrorCode {
  const object = record(value);
  const error = record(object.error);
  if (Object.keys(object).length !== 1 || Object.keys(error).length !== 1 || typeof error.code !== "string") throw new ShareTransportError("unknown");
  const mapping: Record<string, TransportErrorCode> = {
    invalid_or_expired_claim: "expired", claim_already_used: "used", invitation_authorization_invalid: "invalid", untrusted_node: "denied", invalid_content_source: "invalid", invalid_holder_proof: "denied", invalid_credential_profile: "denied", policy_denied: "denied", nonce_already_used: "used", read_denied: "denied", capability_unavailable: "capability-unavailable",
  };
  const mapped = mapping[error.code];
  if (mapped === undefined) throw new ShareTransportError("unknown");
  return mapped;
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
  try {
    const body = await response.text();
    if (new TextEncoder().encode(body).length > 1_048_576) throw new Error("response-too-large");
    const parsed = JSON.parse(body) as unknown;
    if (!response.ok) throw new ShareTransportError(parseFailure(parsed), response.status >= 500 || response.status === 429, retryAfter(response.headers.get("Retry-After")));
    return parsed as T;
  } catch (error) {
    if (error instanceof ShareTransportError && error.code !== "unknown") throw error;
    if (!response.ok) throw new ShareTransportError(codeFor(response.status), response.status >= 500 || response.status === 429, retryAfter(response.headers.get("Retry-After")));
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

function parseActivationAccepted(value: unknown): { readonly status: "accepted"; readonly retryAfterSeconds: number; readonly activationId: string } {
  const object = exact(value, ["status", "retryAfterSeconds", "activationId"]);
  const retryAfterSeconds = object.retryAfterSeconds;
  if (object.status !== "accepted" || typeof retryAfterSeconds !== "number" || !Number.isInteger(retryAfterSeconds) || retryAfterSeconds < 0 || retryAfterSeconds > 3600 || typeof object.activationId !== "string" || !/^[A-Za-z0-9_-]{22}$/.test(object.activationId)) throw new ShareTransportError("unknown");
  return { status: "accepted", retryAfterSeconds, activationId: object.activationId };
}

function parseClaimChallenge(value: unknown): ClaimChallengeResponse {
  const object = exact(value, ["claimNonce", "shareCid", "shareId", "policyCid", "delegationCid", "authorityMaterialHandle", "authorityMaterialDigest", "contentSource", "contentSourceDigest", "emailHash", "targetOrigin", "nodeAudience", "expiresAt"]);
  for (const key of ["claimNonce", "shareCid", "shareId", "policyCid", "delegationCid", "authorityMaterialHandle", "authorityMaterialDigest", "contentSourceDigest", "emailHash", "targetOrigin", "nodeAudience", "expiresAt"]) text(object[key]);
  let source: ContentSource;
  try { source = validateSource(object.contentSource as ContentSource); } catch { throw new ShareTransportError("unknown"); }
  if (!/^[A-Za-z0-9_-]{43}$/.test(object.claimNonce as string) || !/^[A-Za-z0-9_-]{43}$/.test(object.emailHash as string)) throw new ShareTransportError("unknown");
  return { ...object, contentSource: source } as unknown as ClaimChallengeResponse;
}

function parseCredential(value: unknown): ClaimCredentialResponse {
  const object = exact(value, ["format", "credential", "holderDid", "expiresAt"]);
  if (object.format !== "vc+sd-jwt") throw new ShareTransportError("unknown");
  const credential = text(object.credential); text(object.holderDid); text(object.expiresAt);
  if (new TextEncoder().encode(credential).length > 65_536) throw new ShareTransportError("unknown");
  return object as unknown as ClaimCredentialResponse;
}

function parseProof(value: unknown): SignedProof {
  const object = exact(value, ["alg", "kid", "signature"]);
  if (object.alg !== "EdDSA" || typeof object.kid !== "string" || !/^did:(?:web|key):[^#\s]+#[^#\s]+$/.test(object.kid) || typeof object.signature !== "string" || !/^[A-Za-z0-9_-]{86}$/.test(object.signature)) throw new ShareTransportError("unknown");
  return object as unknown as SignedProof;
}

function parseAuthorization(value: unknown): AuthorizedInvitation {
  const outer = exact(value, ["authorization", "proof"]);
  const authorization = exact(outer.authorization, ["type", "version", "jti", "senderDid", "shareCid", "shareId", "policyCid", "delegationCid", "authorityMaterialHandle", "authorityMaterialDigest", "recipientEmail", "targetOrigin", "nodeAudience", "returnOrigin", "documentName", "senderTrust", "contentSource", "contentSourceDigest", "shareExpiresAt", "issuedAt", "expiresAt", "reportAbuseToken"]);
  if (authorization.type !== "TinyCloudShareInviteAuthorization" || authorization.version !== 1 || authorization.senderTrust !== "verified" && authorization.senderTrust !== "unverified") throw new ShareTransportError("unknown");
  try { validateSource(authorization.contentSource as ContentSource); } catch { throw new ShareTransportError("unknown"); }
  return { authorization: { ...authorization, contentSource: validateSource(authorization.contentSource as ContentSource) } as never, proof: parseProof(outer.proof) };
}

function parsePolicyChallenge(value: unknown): { readonly challenge: Record<string, unknown>; readonly proof: SignedProof } {
  const object = exact(value, ["challenge", "proof"]);
  const challenge = exact(object.challenge, ["type", "version", "challengeId", "nonce", "shareCid", "shareId", "delegationCid", "policyCid", "authorityMaterialHandle", "authorityMaterialDigest", "contentSource", "contentSourceDigest", "holderDid", "targetOrigin", "nodeAudience", "action", "resource", "requestBodyDigest", "issuedAt", "expiresAt", "enforcerDid"]);
  text(challenge.enforcerDid);
  return { challenge, proof: parseProof(object.proof) };
}

function parsePolicySession(value: unknown): { readonly session: Record<string, unknown>; readonly proof: SignedProof } {
  const object = exact(value, ["session", "proof"]);
  return { session: exact(object.session, ["type", "version", "sessionId", "shareCid", "shareId", "delegationCid", "policyCid", "authorityMaterialHandle", "authorityMaterialDigest", "contentSource", "contentSourceDigest", "holderDid", "targetOrigin", "nodeAudience", "action", "resource", "credentialDigest", "issuedAt", "expiresAt"]), proof: parseProof(object.proof) };
}

function parseRead(value: unknown): ReadResponse {
  const object = exact(value, ["type", "version", "sessionId", "requestJti", "readJti", "audience", "holderDid", "credentialDigest", "issuedAt", "expiresAt", "mediaType", "content", "contentSource", "contentSourceDigest", "action", "resource", "requestBodyDigest", "bodyDigest", "delegationCid", "authorityMaterialHandle", "authorityMaterialDigest", "proof"]);
  if (object.type !== "TinyCloudShareReadResponse" || object.version !== 1 || object.mediaType !== "text/markdown; charset=utf-8" || typeof object.content !== "string" || new TextEncoder().encode(object.content).length > 1_048_576) throw new ShareTransportError("unknown");
  for (const key of ["sessionId", "requestJti", "readJti", "audience", "holderDid", "credentialDigest", "issuedAt", "expiresAt", "contentSourceDigest", "resource", "requestBodyDigest", "bodyDigest", "delegationCid", "authorityMaterialHandle", "authorityMaterialDigest"]) text(object[key]);
  if (object.action !== "tinycloud.kv/get" && object.action !== "tinycloud.sql/read") throw new ShareTransportError("unknown");
  let contentSource: ContentSource;
  try { contentSource = validateSource(object.contentSource as ContentSource); } catch { throw new ShareTransportError("unknown"); }
  return { ...object, contentSource, proof: parseProof(object.proof) } as unknown as ReadResponse;
}

export function createHttpTransport(input: { readonly nodeOrigin: string; readonly credentialsOrigin: string; readonly fetchFn?: typeof fetch }): ShareTransport {
  for (const origin of [input.nodeOrigin, input.credentialsOrigin]) {
    const parsed = new URL(origin);
    const sameOriginProxy = typeof globalThis.location !== "undefined" && parsed.origin === globalThis.location.origin;
    if ((parsed.protocol !== "https:" && !sameOriginProxy) || parsed.origin !== origin) throw new TypeError("Trusted service origins must be canonical HTTPS origins or the same-origin Share proxy.");
  }
  const fetchFn = input.fetchFn ?? globalThis.fetch.bind(globalThis);
  const postNode = <T>(path: string, body: Record<string, unknown>) => jsonRequest<T>(fetchFn, input.nodeOrigin, path, { method: "POST", body: JSON.stringify(body) });
  const postCredentials = <T>(path: string, body: Record<string, unknown>) => jsonRequest<T>(fetchFn, input.credentialsOrigin, path, { method: "POST", body: JSON.stringify(body) });
  return {
    authorizeInvitation: async (body) => parseAuthorization(await postNode<unknown>("/share/v1/invitations/authorize", body)),
    requestDelivery: async (body) => parseAccepted(await postCredentials("/v1/share-email/invitations", body)),
    resend: async (body) => parseAccepted(await postCredentials("/v1/share-email/invitations/resend", body)),
    activate: async (body) => parseActivationAccepted(await postCredentials("/v1/share-email/claims/activate", body)),
    claimChallenge: async (body) => parseClaimChallenge(await postCredentials("/v1/share-email/claims/challenge", body)),
    claimRedeem: async (body) => parseCredential(await postCredentials("/v1/share-email/claims/redeem", body)),
    policyChallenge: async (body) => parsePolicyChallenge(await postNode("/share/v1/policy/challenges", body)),
    policySession: async (body) => parsePolicySession(await postNode("/share/v1/policy/session", body)),
    read: async (body) => parseRead(await postNode("/share/v1/read", body)),
  };
}

export function mapTransportFailure(error: unknown): ShareTransportError {
  return error instanceof ShareTransportError ? error : new ShareTransportError("unknown", false);
}
