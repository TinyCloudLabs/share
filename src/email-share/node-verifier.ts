import { canonicalize, fromBase64Url, toBase64Url } from "@tinycloud/share-envelope";
import { ed25519 } from "@noble/curves/ed25519";
import type { ContentSource, SignedProof, TrustedNode } from "./protocol.js";
import type { VerifiedExactEmailShare } from "./verified-share.js";

export const NODE_CLOCK_SKEW_SECONDS = 30;
export const POLICY_CHALLENGE_TTL_SECONDS = 120;
export const POLICY_SESSION_TTL_SECONDS = 300;
export const READ_INVOCATION_TTL_SECONDS = 60;

export class NodeVerificationError extends Error {
  readonly code = "node-response-invalid" as const;

  constructor() {
    super("The trusted node response could not be verified.");
    this.name = "NodeVerificationError";
  }
}

function object(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new NodeVerificationError();
  return value as Record<string, unknown>;
}

function exact(value: unknown, required: readonly string[], optional: readonly string[] = []): Record<string, unknown> {
  const result = object(value);
  const allowed = new Set([...required, ...optional]);
  if (required.some((key) => !Object.hasOwn(result, key)) || Object.keys(result).some((key) => !allowed.has(key))) {
    throw new NodeVerificationError();
  }
  return result;
}

function string(value: unknown): string {
  if (typeof value !== "string" || value.length === 0) throw new NodeVerificationError();
  return value;
}

function timestamp(value: unknown): number {
  const text = string(value);
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(text)) throw new NodeVerificationError();
  const parsed = Date.parse(text);
  if (!Number.isFinite(parsed)) throw new NodeVerificationError();
  return parsed;
}

function equalField(actual: unknown, expected: unknown): void {
  if (typeof actual === "object" || typeof expected === "object") {
    if (canonicalize(actual) !== canonicalize(expected)) throw new NodeVerificationError();
    return;
  }
  if (actual !== expected) throw new NodeVerificationError();
}

export async function digest(value: unknown): Promise<string> {
  return toBase64Url(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonicalize(value)))));
}

export async function digestText(value: string): Promise<string> {
  return toBase64Url(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value))));
}

export async function digestBytes(value: Uint8Array): Promise<string> {
  return toBase64Url(new Uint8Array(await crypto.subtle.digest("SHA-256", value.buffer as ArrayBuffer)));
}

export function requestBodyWithoutDigest(input: Record<string, unknown>): Record<string, unknown> {
  const { requestBodyDigest: _ignored, ...body } = input;
  return body;
}

export async function verifyNodeProof(
  message: unknown,
  proof: SignedProof,
  trust: TrustedNode,
  domain: string,
): Promise<void> {
  if (!trust.enabled || proof.alg !== "EdDSA" || proof.kid !== trust.invitationKid) throw new NodeVerificationError();
  let signature: Uint8Array;
  try { signature = fromBase64Url(proof.signature); } catch { throw new NodeVerificationError(); }
  if (signature.length !== 64 || trust.invitationPublicKey.length !== 32) throw new NodeVerificationError();
  const bytes = new TextEncoder().encode(`${domain}${canonicalize(message)}`);
  try {
    if (!ed25519.verify(signature, bytes, trust.invitationPublicKey, { zip215: false })) throw new NodeVerificationError();
  } catch { throw new NodeVerificationError(); }
}

export function assertTrustedNodeScope(share: VerifiedExactEmailShare, trust: TrustedNode): void {
  if (!trust.enabled || trust.targetOrigin !== share.nodeOrigin || trust.nodeAudience !== share.nodeAudience) throw new NodeVerificationError();
}

export function assertNodeTime(issuedAt: unknown, expiresAt: unknown, now = Date.now(), maxTtlSeconds: number): void {
  const issued = timestamp(issuedAt);
  const expires = timestamp(expiresAt);
  if (issued > now + NODE_CLOCK_SKEW_SECONDS * 1000 || expires <= now - NODE_CLOCK_SKEW_SECONDS * 1000 || expires <= issued || expires - issued > maxTtlSeconds * 1000) {
    throw new NodeVerificationError();
  }
}

export function assertCommonNodeBinding(
  message: Record<string, unknown>,
  share: VerifiedExactEmailShare,
  holderDid: string,
): void {
  const expected: Record<string, unknown> = {
    shareCid: share.shareCid,
    shareId: share.shareId,
    policyCid: share.policyCid,
    delegationCid: share.delegationCid,
    authorityMaterialHandle: share.authorityMaterialHandle,
    authorityMaterialDigest: share.authorityMaterialDigest,
    contentSource: share.contentSource,
    contentSourceDigest: share.contentSourceDigest,
    holderDid,
    targetOrigin: share.nodeOrigin,
    nodeAudience: share.nodeAudience,
    action: share.action,
    resource: share.resource,
  };
  for (const [key, value] of Object.entries(expected)) equalField(message[key], value);
}

export function assertSourceBinding(source: unknown, expected: ContentSource, expectedDigest: string): void {
  equalField(source, expected);
  if (typeof source !== "object" || source === null || Array.isArray(source)) throw new NodeVerificationError();
  if (typeof (source as { action?: unknown }).action !== "string") throw new NodeVerificationError();
  if (typeof (source as { path?: unknown }).path !== "string") throw new NodeVerificationError();
  if (expectedDigest.length !== 43) throw new NodeVerificationError();
}

export function assertCredentialDigest(actual: unknown, expected: string): void {
  if (actual !== expected) throw new NodeVerificationError();
}

export function readResponseBody(value: Record<string, unknown>): Record<string, unknown> {
  const { proof: _proof, ...body } = value;
  return body;
}

export function assertReadResponseBinding(value: unknown, share: VerifiedExactEmailShare, expected?: { readonly sessionId: string; readonly holderDid: string; readonly credentialDigest: string; readonly requestBodyDigest: string; readonly requestJti: string }): { readonly content: string; readonly bodyDigest: string } {
  const response = exact(value, ["type", "version", "sessionId", "requestJti", "readJti", "audience", "holderDid", "credentialDigest", "issuedAt", "expiresAt", "mediaType", "content", "contentSource", "contentSourceDigest", "action", "resource", "requestBodyDigest", "bodyDigest", "delegationCid", "authorityMaterialHandle", "authorityMaterialDigest", "proof"]);
  if (response.type !== "TinyCloudShareReadResponse" || response.version !== 1 || response.mediaType !== "text/markdown; charset=utf-8" || typeof response.content !== "string" || new TextEncoder().encode(response.content).length > 1_048_576) throw new NodeVerificationError();
  equalField(response.delegationCid, share.delegationCid);
  equalField(response.authorityMaterialHandle, share.authorityMaterialHandle);
  equalField(response.authorityMaterialDigest, share.authorityMaterialDigest);
  equalField(response.contentSourceDigest, share.contentSourceDigest);
  equalField(response.contentSource, share.contentSource);
  equalField(response.action, share.action);
  equalField(response.resource, share.resource);
  equalField(response.audience, share.nodeAudience);
  if (expected !== undefined) {
    equalField(response.sessionId, expected.sessionId);
    equalField(response.holderDid, expected.holderDid);
    equalField(response.credentialDigest, expected.credentialDigest);
    equalField(response.requestBodyDigest, expected.requestBodyDigest);
    equalField(response.requestJti, expected.requestJti);
  }
  assertNodeTime(response.issuedAt, response.expiresAt, Date.now(), READ_INVOCATION_TTL_SECONDS);
  if (typeof response.bodyDigest !== "string" || response.bodyDigest.length !== 43) throw new NodeVerificationError();
  return { content: response.content, bodyDigest: response.bodyDigest };
}

export function assertTimestamp(value: unknown): number { return timestamp(value); }
