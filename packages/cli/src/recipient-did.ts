import {
  canonicalMainnetPkhDid,
  canonicalNodeAudienceForOrigin,
  encodeShareUrl,
  generateKey,
  isCanonicalMainnetSpaceId,
  recipientDidEnvelopeV2Schema,
  seal,
  toBase64Url,
  verifyRecipientDidEnvelopeV2,
  type NativeVerifiedRecipientBundleV2,
  type RecipientDidDelegationBundleV2,
  type RecipientDidEnvelopeV2,
} from "@tinycloud/share-envelope";
import { putBlob } from "@tinycloud/share-registry";

import { DEFAULT_EXPIRES_MS } from "./create.js";

const DEFAULT_VIEWER_ORIGIN = "https://share.tinycloud.xyz";
const READ_ACTIONS = ["tinycloud.kv/get"] as const;

/** Fixed-purpose sender boundary. It exposes neither session keys nor raw signing. */
export interface RecipientDidSenderAdapter {
  /** Create the exact recipient delegation and session-sign the complete v2 envelope. */
  createAndSignEnvelope(input: RecipientDidEnvelopeRequest): Promise<RecipientDidEnvelopeV2>;
  /** The same atomic, network-free native verification used by the viewer. */
  verifyDelegationBundle(
    bundle: RecipientDidDelegationBundleV2,
    now: Date,
  ): Promise<NativeVerifiedRecipientBundleV2>;
  /** Copy bytes into the sender's signed exact TinyCloud path. */
  putExact(input: RecipientDidPutRequest): Promise<void>;
}

export interface RecipientDidEnvelopeRequest {
  shareId: string;
  recipientDid: string;
  target: {
    origin: string;
    nodeAudience: string;
    spaceId: string;
    resource: { kind: "exact"; path: string };
    actions: readonly ["tinycloud.kv/get"];
  };
  display: { senderName?: string; filename: string; recipientHint?: string };
  expiry: string;
}

export interface RecipientDidPutRequest {
  origin: string;
  nodeAudience: string;
  spaceId: string;
  path: string;
  content: Uint8Array;
  redirect: "error";
}

export interface CreateRecipientDidShareOptions {
  content: Uint8Array;
  filename: string;
  recipientDid: string;
  origin: string;
  nodeAudience: string;
  spaceId: string;
  registryBaseUrl: string;
  adapter: RecipientDidSenderAdapter;
  expiresAt?: Date;
  senderName?: string;
  recipientHint?: string;
  viewerOrigin?: string;
  allowedOrigins: readonly string[];
  fetchFn?: typeof globalThis.fetch;
  now?: () => number;
  onKeyBuffer?: (key: Uint8Array) => void;
}

export interface CreateRecipientDidShareResult {
  url: string;
  shareId: string;
  envelopeCid: string;
  expiry: string;
  registryDeleteAfter: string;
  envelope: RecipientDidEnvelopeV2;
}

function assertSafeFilename(filename: string): void {
  if (filename.length === 0 || filename === "." || filename === ".." || /[/\\\u0000]/.test(filename)) {
    throw new TypeError("filename must be one safe path segment");
  }
}

function expectedEnvelopeFieldsMatch(
  envelope: RecipientDidEnvelopeV2,
  request: RecipientDidEnvelopeRequest,
): boolean {
  return envelope.shareId === request.shareId &&
    envelope.authorizationTarget.did === request.recipientDid &&
    envelope.target.origin === request.target.origin &&
    envelope.target.nodeAudience === request.target.nodeAudience &&
    envelope.target.spaceId === request.target.spaceId &&
    envelope.target.resource.kind === "exact" &&
    envelope.target.resource.path === request.target.resource.path &&
    envelope.target.actions.length === 1 &&
    envelope.target.actions[0] === READ_ACTIONS[0] &&
    envelope.expiry === request.expiry &&
    envelope.display.filename === request.display.filename &&
    envelope.display.senderName === request.display.senderName &&
    envelope.display.recipientHint === request.display.recipientHint;
}

export async function createRecipientDidShare(
  options: CreateRecipientDidShareOptions,
): Promise<CreateRecipientDidShareResult> {
  assertSafeFilename(options.filename);
  if (options.content.byteLength === 0) throw new TypeError("content is empty");
  if (canonicalMainnetPkhDid(options.recipientDid) !== options.recipientDid) {
    throw new TypeError("recipientDid must be the canonical chain-1 account DID");
  }
  if (!isCanonicalMainnetSpaceId(options.spaceId)) {
    throw new TypeError("spaceId must be a canonical chain-1 TinyCloud space");
  }
  if (canonicalNodeAudienceForOrigin(options.origin) !== options.nodeAudience) {
    throw new TypeError("nodeAudience must exactly match the canonical node origin");
  }
  if (!options.allowedOrigins.includes(options.origin)) {
    throw new TypeError("origin is not in this deployment's static allowlist");
  }

  const nowMs = options.now?.() ?? Date.now();
  const requestedExpiresAt = options.expiresAt ?? new Date(nowMs + DEFAULT_EXPIRES_MS);
  const requestedExpiryMs = requestedExpiresAt.getTime();
  const expiryMs = Math.floor(requestedExpiryMs / 1_000) * 1_000;
  if (!Number.isFinite(requestedExpiryMs) || expiryMs <= nowMs) {
    throw new RangeError("expiresAt must be a valid future time");
  }
  // TinyCloud UCAN numeric dates have whole-second precision. Derive one
  // canonical instant and reuse it for the grant, envelope, and registry so
  // no layer can disagree after independently truncating milliseconds.
  const expiry = new Date(expiryMs).toISOString();
  const shareId = toBase64Url(globalThis.crypto.getRandomValues(new Uint8Array(16)));
  const path = `shares/${shareId}/${options.filename}`;
  const request: RecipientDidEnvelopeRequest = {
    shareId,
    recipientDid: options.recipientDid,
    target: {
      origin: options.origin,
      nodeAudience: options.nodeAudience,
      spaceId: options.spaceId,
      resource: { kind: "exact", path },
      actions: READ_ACTIONS,
    },
    display: {
      filename: options.filename,
      ...(options.senderName !== undefined && options.senderName.length > 0
        ? { senderName: options.senderName }
        : {}),
      ...(options.recipientHint !== undefined && options.recipientHint.length > 0
        ? { recipientHint: options.recipientHint }
        : {}),
    },
    expiry,
  };

  const envelope = recipientDidEnvelopeV2Schema.parse(
    await options.adapter.createAndSignEnvelope(request),
  );
  if (!expectedEnvelopeFieldsMatch(envelope, request)) {
    throw new Error("SDK returned an envelope that differs from the requested share");
  }
  const verified = await verifyRecipientDidEnvelopeV2(envelope, {
    allowedOrigins: options.allowedOrigins,
    now: new Date(nowMs),
    verifyDelegationBundle: (bundle, verificationTime) =>
      options.adapter.verifyDelegationBundle(bundle, verificationTime),
  });
  if (!verified.ok) {
    throw new Error(`SDK returned an invalid recipient share (${verified.code})`);
  }

  // The registry never receives recipient content. Publish the link only
  // after the exact TinyCloud copy succeeds.
  await options.adapter.putExact({
    origin: options.origin,
    nodeAudience: options.nodeAudience,
    spaceId: options.spaceId,
    path,
    content: options.content,
    redirect: "error",
  });

  const envelopeKey = generateKey();
  options.onKeyBuffer?.(envelopeKey);
  try {
    const sealed = await seal(new TextEncoder().encode(JSON.stringify(envelope)), envelopeKey);
    const put = await putBlob(options.registryBaseUrl, sealed.blob, expiry, {
      ...(options.fetchFn !== undefined ? { fetchFn: options.fetchFn } : {}),
    });
    return {
      url: encodeShareUrl({
        origin: options.viewerOrigin ?? DEFAULT_VIEWER_ORIGIN,
        ciphertextCid: sealed.cid,
        key32: envelopeKey,
      }),
      shareId,
      envelopeCid: sealed.cid,
      expiry,
      registryDeleteAfter: put.deleteAfter,
      envelope,
    };
  } finally {
    envelopeKey.fill(0);
  }
}
