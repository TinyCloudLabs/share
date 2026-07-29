import {
  checkBearerDelegation,
  computeCid,
  fromBase64Url,
  open,
  parseCompactOrInlineShareUrl,
  shareEnvelopeSchema,
  verifyEnvelope,
  type ShareEnvelope,
} from "@tinycloud/share-envelope";
import { CidMismatchError, RegistryHttpError, fetchBlob } from "@tinycloud/share-registry";

export type ShareErrorCode = "invalid-link" | "fetch-failed" | "max-bytes-exceeded" | "cid-mismatch" | "decrypt-failed" | "envelope-invalid" | "origin-mismatch" | "signature-invalid" | "capability-invalid" | "expired" | "unsupported-target" | "content-integrity-failed";

export class ShareReceiveError extends Error {
  readonly code: ShareErrorCode;
  readonly details: { readonly expiresAt?: string; readonly stage?: "content" } | undefined;
  constructor(code: ShareErrorCode, message: string, details?: { readonly expiresAt?: string; readonly stage?: "content" }) {
    super(message);
    this.name = "ShareReceiveError";
    this.code = code;
    this.details = details;
  }
}

export interface ShareFetchOptions {
  readonly registryBaseUrl: string;
  readonly fetchFn?: typeof globalThis.fetch;
  readonly expectedOrigin?: string;
  readonly now?: () => number;
  readonly onKeyParsed?: (key32: Uint8Array) => void;
}

export interface ShareMetadata {
  readonly protocol: "tinycloud-share";
  readonly version: 1;
  readonly shareId: string;
  readonly origin: string;
  readonly target: ShareEnvelope["target"];
  readonly resource: ShareEnvelope["target"]["resource"];
  readonly actions: readonly ["read"];
  readonly expiresAt: string;
  readonly display: ShareEnvelope["display"];
  readonly content?: { readonly cid: string };
}

export interface ShareInspection {
  readonly metadata: ShareMetadata;
  readonly link: { readonly origin: string; readonly cid: string; readonly kind: "compact" | "inline" };
}

export interface ShareReceiveResult extends ShareInspection {
  readonly bytes: Uint8Array;
  readonly text?: string;
}

function metadataFor(envelope: ShareEnvelope, origin: string): ShareMetadata {
  return {
    protocol: "tinycloud-share",
    version: 1,
    shareId: envelope.shareId,
    origin,
    target: envelope.target,
    resource: envelope.target.resource,
    actions: ["read"],
    expiresAt: envelope.expiry,
    display: {
      ...(envelope.display.senderName === undefined ? {} : { senderName: envelope.display.senderName }),
      ...(envelope.display.filename === undefined ? {} : { filename: envelope.display.filename }),
      ...(envelope.display.mode === undefined ? {} : { mode: envelope.display.mode }),
    },
    ...(envelope.content === undefined ? {} : { content: { cid: envelope.content.cid } }),
  };
}

async function resolveEnvelope(link: string, options: ShareFetchOptions): Promise<{ envelope: ShareEnvelope; origin: string; cid: string; kind: "compact" | "inline" }> {
  let parsed: ReturnType<typeof parseCompactOrInlineShareUrl>;
  try { parsed = parseCompactOrInlineShareUrl(link, { ...(options.expectedOrigin === undefined ? {} : { expectedOrigin: options.expectedOrigin }) }); }
  catch { throw new ShareReceiveError("invalid-link", "share link format is invalid"); }
  try {
    if (parsed.key32 !== undefined) options.onKeyParsed?.(parsed.key32);
    const url = new URL(link);
    const sealed = parsed.kind === "inline" ? parsed.ciphertext : await fetchBlob(options.registryBaseUrl, parsed.ciphertextCid, { ...(options.fetchFn === undefined ? {} : { fetchFn: options.fetchFn }) });
    if (await computeCid(sealed) !== parsed.ciphertextCid) throw new ShareReceiveError("cid-mismatch", "registry bytes do not match the link CID");
    let plaintext: Uint8Array;
    try { plaintext = await open(sealed, parsed.key32!); } catch { throw new ShareReceiveError("decrypt-failed", "share envelope could not be opened"); }
    let envelope: ShareEnvelope;
    try { envelope = shareEnvelopeSchema.parse(JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(plaintext))); }
    catch { throw new ShareReceiveError("envelope-invalid", "share envelope is invalid"); }
    return { envelope, origin: url.origin, cid: parsed.ciphertextCid, kind: parsed.kind };
  } finally {
    parsed.key32?.fill(0);
  }
}

async function verify(envelope: ShareEnvelope, origin: string, options: ShareFetchOptions): Promise<void> {
  if (envelope.target.origin !== origin || (options.expectedOrigin !== undefined && options.expectedOrigin !== origin)) throw new ShareReceiveError("origin-mismatch", "share origin does not match its signed target");
  if (envelope.authorizationTarget.kind !== "bearerKey" || envelope.target.resource.kind !== "exact") throw new ShareReceiveError("unsupported-target", "this receive path only handles bearer exact shares");
  try { if (!await verifyEnvelope(envelope, { expectedSignerDid: envelope.signature.signerDid })) throw new Error("signature"); }
  catch { throw new ShareReceiveError("signature-invalid", "share signature is invalid"); }
  const now = options.now?.() ?? Date.now();
  if (Date.parse(envelope.expiry) <= now) throw new ShareReceiveError("expired", "share has expired", { expiresAt: envelope.expiry });
  if (!checkBearerDelegation(envelope, { now: () => now }).ok) throw new ShareReceiveError("capability-invalid", "share delegation does not authorize the target");
}

export async function inspectShare(link: string, options: ShareFetchOptions): Promise<ShareInspection> {
  const resolved = await resolveEnvelope(link, options);
  await verify(resolved.envelope, resolved.origin, options);
  return { metadata: metadataFor(resolved.envelope, resolved.origin), link: { origin: resolved.origin, cid: resolved.cid, kind: resolved.kind } };
}

export async function receiveShare(link: string, options: ShareFetchOptions): Promise<ShareReceiveResult> {
  const resolved = await resolveEnvelope(link, options);
  await verify(resolved.envelope, resolved.origin, options);
  let bytes: Uint8Array<ArrayBufferLike> = new Uint8Array();
  if (resolved.envelope.content !== undefined) {
    try {
      bytes = await fetchBlob(options.registryBaseUrl, resolved.envelope.content.cid, { ...(options.fetchFn === undefined ? {} : { fetchFn: options.fetchFn }) });
      if (await computeCid(bytes) !== resolved.envelope.content.cid) throw new Error("cid");
      const key = fromBase64Url(resolved.envelope.content.key);
      try { bytes = await open(bytes, key); } finally { key.fill(0); }
    } catch (error) {
      if (error instanceof ShareReceiveError) throw error;
      if (error instanceof RegistryHttpError) throw new ShareReceiveError("fetch-failed", "shared content is unavailable", { stage: "content" });
      if (error instanceof CidMismatchError) throw new ShareReceiveError("content-integrity-failed", "shared content CID does not match");
      throw new ShareReceiveError("content-integrity-failed", "shared content could not be opened");
    }
  }
  let text: string | undefined;
  if (bytes.byteLength !== 0) {
    try { text = new TextDecoder("utf-8", { fatal: true }).decode(bytes); } catch { /* binary content */ }
  }
  return { metadata: metadataFor(resolved.envelope, resolved.origin), link: { origin: resolved.origin, cid: resolved.cid, kind: resolved.kind }, bytes, ...(text === undefined ? {} : { text }) };
}

