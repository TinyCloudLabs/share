import {
  canonicalize,
  computeCid,
  encodeInlineShareUrl,
  encodeShareUrl,
  generateKey,
  seal,
  shareEnvelopeV2Schema,
  toBase64Url,
  unsignedShareEnvelopeV2Schema,
  type RecipientMatcher,
  type ResourceSelector,
  type ShareAction as EnvelopeAction,
  type ShareEnvelopeV2,
} from "@tinycloud/share-envelope";
import type { ContentSource, SenderScope } from "../../../src/email-share/protocol.js";

export interface AddressedSharePolicy {
  readonly policyCid: string;
  readonly policyBytes: string;
  readonly policyDigest?: string;
}

export interface CreateAddressedShareLinkInput {
  readonly matcher: RecipientMatcher;
  readonly deliveryEmail?: string;
  readonly source: ContentSource;
  readonly scope: SenderScope;
  readonly policy: AddressedSharePolicy;
  readonly actions: readonly EnvelopeAction[];
  readonly resource: ResourceSelector;
  readonly shareId: string;
  readonly expiresAt: string;
  readonly filename: string;
  readonly mediaType: string;
  readonly byteLength: number;
  readonly encrypted: boolean;
  readonly format: "compact" | "inline";
  readonly uploadEnvelope: (cid: string, blob: Uint8Array, deleteAfter: string) => Promise<void>;
  readonly publishBinding?: (binding: Record<string, unknown>) => Promise<void>;
}

export interface AddressedShareLink {
  readonly shareUrl: string;
  readonly shareCid: string;
  readonly envelope: ShareEnvelopeV2;
  readonly recipientMatcher: RecipientMatcher;
  readonly deliveryEmail?: string;
  readonly source: ContentSource;
  readonly actions: readonly EnvelopeAction[];
  readonly resource: ResourceSelector;
  readonly expiresAt: string;
}

const ACTION_ORDER: readonly EnvelopeAction[] = ["read", "list", "edit"];

function orderedActions(actions: readonly EnvelopeAction[]): readonly EnvelopeAction[] {
  const result = ACTION_ORDER.filter((action) => actions.includes(action));
  if (result.length === 0 || result.length !== new Set(actions).size || actions.some((action) => !ACTION_ORDER.includes(action))) {
    throw new TypeError("The addressed share must grant at least one supported action.");
  }
  return result;
}

function assertResource(resource: ResourceSelector): void {
  const body = resource.kind === "prefix" && resource.path.endsWith("/") ? resource.path.slice(0, -1) : resource.path;
  if (body.length === 0 || body.split("/").some((segment) => segment.length === 0 || segment === "." || segment === "..") || /[\\\u0000-\u001f\u007f]/.test(body) || /%2f|%5c|%2e/i.test(body)) {
    throw new TypeError("The addressed share resource is not canonical.");
  }
}

function assertExpiry(value: string, scope: SenderScope): void {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value) || !Number.isFinite(Date.parse(value))) throw new TypeError("The addressed share expiry is invalid.");
  const expiry = Date.parse(value);
  for (const bound of [scope.expiryMin, scope.expiryMax, scope.expiresAt]) {
    if (bound !== undefined && (!Number.isFinite(Date.parse(bound)) || expiry > Date.parse(bound))) throw new TypeError("The addressed share expiry exceeds the authenticated capability.");
  }
}

/**
 * Builds the v2 addressed envelope from the actual composer selection. The
 * server-provided policy remains authoritative; the browser only narrows its
 * action/resource/matcher request and never promotes UI claims to authority.
 */
export async function createAddressedShareLink(input: CreateAddressedShareLinkInput): Promise<AddressedShareLink> {
  if (input.scope.spaceId !== input.source.space) throw new TypeError("The selected resource is outside the authorized space.");
  if (input.policy.policyCid.length === 0 || input.policy.policyBytes.length === 0) throw new TypeError("Authoritative policy material is required.");
  assertResource(input.resource);
  assertExpiry(input.expiresAt, input.scope);
  const actions = orderedActions(input.actions);
  if (!input.encrypted && (input.format !== "inline" || input.matcher.kind !== "policyDigest")) {
    throw new TypeError("Plaintext policy metadata must use an inline policy-digest link.");
  }
  if (!input.encrypted && (input.deliveryEmail !== undefined || input.byteLength !== 0 || input.filename.length !== 0)) {
    throw new TypeError("Plaintext policy metadata cannot contain delivery or content details.");
  }
  const metadata = input.encrypted
    ? { mediaType: input.mediaType, byteLength: input.byteLength, filename: input.filename, encoding: input.mediaType.startsWith("text/") ? "utf-8" as const : undefined }
    : {};
  const unsigned = {
    version: 2 as const,
    shareId: input.shareId,
    recipientMatcher: input.matcher,
    ...(input.deliveryEmail === undefined ? {} : { deliveryEmail: input.deliveryEmail }),
    actions: [...actions],
    resource: input.resource,
    target: {
      origin: input.scope.targetOrigin,
      nodeAudience: input.scope.nodeAudience,
      spaceId: input.scope.spaceId,
    },
    delegationCid: input.scope.delegationCid,
    authorityMaterialHandle: input.scope.authorityMaterialHandle,
    authorityMaterialDigest: input.scope.authorityMaterialDigest,
    contentSource: input.source,
    contentSourceDigest: await digestSource(input.source),
    authorizationTarget: { kind: "policy" as const, policyCid: input.policy.policyCid, policyBytes: input.policy.policyBytes },
    display: input.encrypted ? { filename: input.filename } : {},
    expiry: input.expiresAt,
    encrypted: input.encrypted,
    metadata,
  };
  const signature = await input.scope.signer.sign({
    purpose: "envelope",
    message: canonicalize(unsigned),
    binding: {
      version: 2,
      shareId: input.shareId,
      recipientMatcher: input.matcher,
      ...(input.deliveryEmail === undefined ? {} : { deliveryEmail: input.deliveryEmail }),
      actions,
      resource: input.resource,
      source: input.source,
      contentSource: input.source,
      contentSourceDigest: await digestSource(input.source),
      policyCid: input.policy.policyCid,
      ...(input.policy.policyDigest === undefined ? {} : { policyDigest: input.policy.policyDigest }),
      expiresAt: input.expiresAt,
      targetOrigin: input.scope.targetOrigin,
      nodeAudience: input.scope.nodeAudience,
      spaceId: input.scope.spaceId,
      delegationCid: input.scope.delegationCid,
      authorityMaterialHandle: input.scope.authorityMaterialHandle,
      authorityMaterialDigest: input.scope.authorityMaterialDigest,
    },
  });
  if (signature.length !== 64) throw new TypeError("The sender signer returned an invalid signature.");
  unsignedShareEnvelopeV2Schema.parse(unsigned);
  const signedEnvelope: ShareEnvelopeV2 = {
    ...unsigned,
    signature: { signerDid: input.scope.senderDid, algorithm: "Ed25519", value: toBase64Url(signature) },
  };
  shareEnvelopeV2Schema.parse(signedEnvelope);
  const envelopeBytes = new TextEncoder().encode(canonicalize(signedEnvelope));
  const key = input.encrypted ? generateKey() : undefined;
  const stored = key === undefined ? { cid: await computeCid(envelopeBytes), blob: envelopeBytes } : await seal(envelopeBytes, key);
  let shareUrl: string;
  try {
    if (input.format === "compact") await input.uploadEnvelope(stored.cid, stored.blob, input.expiresAt);
    shareUrl = key === undefined
      ? await encodeInlineShareUrl({ origin: input.scope.shareOrigin, ciphertext: stored.blob })
      : input.format === "inline"
        ? await encodeInlineShareUrl({ origin: input.scope.shareOrigin, ciphertext: stored.blob, key32: key })
        : encodeShareUrl({ origin: input.scope.shareOrigin, ciphertextCid: stored.cid, key32: key });
  } finally {
    key?.fill(0);
  }
  await input.publishBinding?.({ version: 2, shareCid: stored.cid, shareId: input.shareId, policyCid: input.policy.policyCid, recipientMatcher: input.matcher, ...(input.deliveryEmail === undefined ? {} : { deliveryEmail: input.deliveryEmail }), actions, resource: input.resource, target: { origin: input.scope.targetOrigin, nodeAudience: input.scope.nodeAudience, spaceId: input.scope.spaceId }, delegationCid: input.scope.delegationCid, authorityMaterialHandle: input.scope.authorityMaterialHandle, authorityMaterialDigest: input.scope.authorityMaterialDigest, contentSource: input.source, contentSourceDigest: await digestSource(input.source), expiry: input.expiresAt });
  return { shareUrl, shareCid: stored.cid, envelope: signedEnvelope, recipientMatcher: input.matcher, ...(input.deliveryEmail === undefined ? {} : { deliveryEmail: input.deliveryEmail }), source: input.source, actions, resource: input.resource, expiresAt: input.expiresAt };
}

async function digestSource(source: ContentSource): Promise<string> {
  const bytes = new TextEncoder().encode(canonicalize(source));
  return toBase64Url(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes.buffer as ArrayBuffer)));
}
