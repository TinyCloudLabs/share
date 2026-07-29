import { armManualCopy, createLinkOnlyShare, copyWithFallback, type CreateLinkOnlyShareOptions, type ManualCopyHandle } from "./link-only.js";
import { createAddressedShareLink, createShareLink, sendShareEmail } from "@tinycloud/share-sdk";
import { canonicalDigest } from "../email-share/protocol.js";
import type { ContentSource, SenderScope } from "../email-share/protocol.js";
import { verifyNodeProof } from "../email-share/node-verifier.js";
import type { SenderPolicy } from "../email-share/sender.js";
import type { OpenKeyShareSession, ShareTinyCloud } from "./openkey-session.js";
import { createTinyCloudUploader } from "./openkey-session.js";
import { fail, senderFailureMessage } from "./sender-failure.js";
import { canonicalize, computeCid, didKeyFromEd25519PublicKey, encodeInlineShareUrl, encodeShareUrl, fromBase64Url, generateKey, seal, shareEnvelopeV2Schema, unsignedShareEnvelopeV2Schema, toBase64Url } from "@tinycloud/share-envelope";
type WebSdkModule = typeof import("@tinycloud/web-sdk");

/**
 * Taken from the SDK rather than restated here. The hand-written copy of this
 * shape typed `actions` as `readonly string[]`, which is wider than the SDK's
 * own `OwnerShareAction` union — a mis-shaped policy would have compiled.
 */
type OwnerSharePolicyV2 = Parameters<WebSdkModule["canonicalOwnerSharePolicy"]>[0];

/**
 * The owner-share primitives `createOwnerPolicyShare` calls, typed by picking
 * them off the real module type. `Pick` fails to compile if the pinned SDK
 * stops exporting one, and every call below is checked against the SDK's own
 * signature instead of a local restatement that can silently drift (TC-343:
 * a hand-written `(input: Record<string, string>)` cast hid two required
 * arguments of `authorizeShareDelivery` from the compiler entirely).
 */
type OwnerSdk = Pick<WebSdkModule, typeof OWNER_SDK_PRIMITIVES[number]>;

/**
 * The names in `OwnerSdk`, as values, so the runtime can report a skew by name.
 * Types are erased at build time and the installed version is whatever npm
 * resolved, so a `^` range that quietly resolves an SDK without these exports
 * (TC-338/TC-343) still has to fail diagnosably rather than as
 * `sdk.createDelegatedShareKey is not a function`.
 */
export const OWNER_SDK_PRIMITIVES = ["createDelegatedShareKey", "canonicalOwnerSharePolicy", "createPolicyEnforcementDelegation"] as const;

/** The owner-share primitives the loaded Web SDK does not provide, in `OWNER_SDK_PRIMITIVES` order. */
export function missingOwnerSdkPrimitives(module: Record<string, unknown>): readonly string[] {
  return OWNER_SDK_PRIMITIVES.filter((name) => typeof module[name] !== "function");
}

/**
 * The owner-share methods the ceremony invokes on the TinyCloud session. Same
 * failure mode as `OWNER_SDK_PRIMITIVES`, one layer over: these are instance
 * methods on `TinyCloudWeb`, so an SDK without them fails inside the ceremony
 * rather than at import.
 */
export const OWNER_TINYCLOUD_METHODS = ["createOwnerDelegation", "registerOwnerSharePolicy"] as const;

/**
 * Deliberately not in `OWNER_TINYCLOUD_METHODS`: delivery is a post-link
 * action, so its absence must not fail share creation. The link is already
 * stable when this is reached.
 */
export const OWNER_TINYCLOUD_DELIVERY_METHODS = ["authorizeShareDelivery"] as const;

/** The Node-signed delivery receipt, as the SDK returns it. `main.ts` forwards `authorization` and `proof` verbatim. */
export type ShareDeliveryAuthorizationReceipt = Awaited<ReturnType<ShareTinyCloud["authorizeShareDelivery"]>>;

/** Which of `names` the TinyCloud session does not provide as callable methods, in `names` order. */
export function missingTinyCloudMethods(tinycloud: unknown, names: readonly string[]): readonly string[] {
  const record = (tinycloud ?? {}) as Record<string, unknown>;
  return names.filter((name) => typeof record[name] !== "function");
}

async function ownerSdk(): Promise<OwnerSdk> {
  const module = await import("@tinycloud/web-sdk");
  const missing = missingOwnerSdkPrimitives(module as unknown as Record<string, unknown>);
  if (missing.length > 0) throw fail("internal", `the installed @tinycloud/web-sdk does not provide the owner-share primitives ${missing.join(", ")}`, { missingOwnerSdkPrimitives: missing });
  return module;
}
import { loadSharePublicConfig } from "../email-share/config.js";
import { createHttpTransport } from "../email-share/transport.js";
import {
  canNotify,
  clampExpiry,
  contentFile,
  contentFilename,
  contentMediaType,
  contentSource,
  defaultComposerModel,
  emailDomainOf,
  expiryFromChoice,
  normalizeEmail,
  normalizeEmailDomain,
  projectCapabilities,
  validateComposerModel,
  EXPIRY_CHOICES,
  DEFAULT_EXPIRY_CHOICE,
  type ComposerContent,
  type ExpiryChoice,
  type RecipientKind,
  type ShareComposerModel,
  type ShareLinkFormat,
  type SharePermission,
} from "./composer-model.js";

export interface ComposerShareResult {
  readonly url: string;
  readonly cid: string;
  readonly format: ShareLinkFormat;
  readonly expiresAt?: string;
  /** The owner delegation CID backing this share, absent for bearer (possession-only) links. Revoking this CID revokes the share and every delegation derived from it. */
  readonly delegationCid?: string;
  /** Explicit, post-link delivery action. The link is already stable before this is called. */
  readonly notify?: () => Promise<void>;
}

export interface ShareComposerOptions extends Omit<CreateLinkOnlyShareOptions, "createShare" | "expiresAt"> {
  readonly openKeyAddress: string;
  /** Leaves the composer for the library. The composer is never a one-way door (P0-1). */
  readonly onBack: () => void;
  readonly session?: OpenKeyShareSession;
  readonly copyText?: (value: string) => Promise<void>;
  readonly createShare?: (input: { readonly file: File | undefined; readonly model: ShareComposerModel }) => Promise<ComposerShareResult>;
  readonly loadCapabilities?: () => Promise<readonly { readonly capabilityId: string; readonly scope: Record<string, unknown>; readonly source: ContentSource; readonly policy: SenderPolicy }[]>;
  readonly notify?: (input: { readonly share: ComposerShareResult; readonly recipient: string; readonly matcher: RecipientKind; readonly deliveryAuthorization?: ShareDeliveryAuthorizationReceipt }) => Promise<void>;
  readonly tinycloud?: ShareTinyCloud;
  readonly persistShare?: (input: { readonly share: ComposerShareResult; readonly model: ShareComposerModel; readonly file: File | undefined }) => Promise<void>;
}

function el<K extends keyof HTMLElementTagNameMap>(doc: Document, tag: K, className: string, text?: string): HTMLElementTagNameMap[K] {
  const node = doc.createElement(tag);
  node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function checkedValues(root: HTMLElement, name: string): string[] {
  return Array.from(root.querySelectorAll<HTMLInputElement>(`input[name="${name}"]:checked`)).map((input) => input.value);
}

function setStatus(node: HTMLElement, title: string, detail: string, state: string, alert = false): void {
  node.dataset.state = state;
  if (alert) node.setAttribute("role", "alert"); else node.removeAttribute("role");
  node.replaceChildren(el(node.ownerDocument, "strong", "sender-status-title", title), el(node.ownerDocument, "span", "sender-status-detail", detail));
}

async function defaultCreate(file: File | undefined, model: ShareComposerModel, options: ShareComposerOptions): Promise<ComposerShareResult> {
  if (model.recipient.kind !== "bearer") {
    if (options.session === undefined) throw fail("session", "addressed share has no session");
    if (model.content.kind !== "library" && file === undefined) throw fail("content", "addressed share has no file");
    return createPolicyShare(file, model, options);
  }
  if (file === undefined) throw fail("content", "link-only share has no file");
  const result = await createLinkOnlyShare(file, {
    origin: options.origin,
    allowBinary: true,
    expiresAt: new Date(model.expiresAt),
    ...(options.now === undefined ? {} : { now: options.now }),
    ...(options.registryOrigin === undefined ? {} : { registryOrigin: options.registryOrigin }),
    ...(options.fetchFn === undefined ? {} : { fetchFn: options.fetchFn }),
  });
  if (model.linkFormat === "inline") {
    if (result.inlineEnvelopeBlob === undefined || result.inlineEnvelopeKey === undefined) throw fail("format", "link-only inline material is missing");
    try {
      const url = await encodeInlineShareUrl({ origin: options.origin, ciphertext: result.inlineEnvelopeBlob, key32: result.inlineEnvelopeKey });
      return { url, cid: result.envelopeCid, format: model.linkFormat, expiresAt: result.expiry };
    } finally {
      result.inlineEnvelopeKey.fill(0);
    }
  }
  return { url: result.url, cid: result.envelopeCid, format: model.linkFormat, expiresAt: result.expiry };
}

function bytes(value: unknown, label: string): Uint8Array {
  if (typeof value === "string") {
    try { return fromBase64Url(value); } catch { throw fail("internal", `${label} is invalid`); }
  }
  if (Array.isArray(value) && value.every((item) => Number.isInteger(item) && item >= 0 && item <= 255)) return Uint8Array.from(value);
  if (typeof value === "object" && value !== null) {
    const entries = Object.entries(value as Record<string, unknown>).sort(([left], [right]) => Number(left) - Number(right));
    if (entries.length > 0 && entries.every(([key, item], index) => key === String(index) && typeof item === "number")) return Uint8Array.from(entries.map(([, item]) => item as number));
  }
  throw fail("internal", `${label} is invalid`);
}

async function digestBytes(value: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength) as ArrayBuffer);
  return toBase64Url(new Uint8Array(digest));
}

async function createPolicyShare(file: File | undefined, model: ShareComposerModel, options: ShareComposerOptions): Promise<ComposerShareResult> {
  if (options.tinycloud !== undefined) return createOwnerPolicyShare(file, model, options);
  const response = options.loadCapabilities === undefined ? await fetch("/api/share/capabilities", { credentials: "include", cache: "no-store", redirect: "error" }) : undefined;
  if (response !== undefined && !response.ok) throw fail("account", "capability list request was rejected");
  const capabilities = options.loadCapabilities === undefined ? ((await response!.json()) as { readonly capabilities?: readonly { readonly capabilityId: string; readonly scope: Record<string, unknown>; readonly source: ContentSource; readonly policy: SenderPolicy }[] }).capabilities ?? [] : await options.loadCapabilities();
  const matcherMatches = (item: { readonly policy: SenderPolicy }): boolean => {
    const policy = item.policy as unknown as Record<string, unknown>;
    let signedPolicy: Record<string, unknown> | undefined;
    if (typeof policy.policyBytes === "string") {
      try {
        const parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(fromBase64Url(policy.policyBytes))) as unknown;
        if (typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)) signedPolicy = parsed as Record<string, unknown>;
      } catch { /* Legacy capability records use recipientEmail below. */ }
    }
    const signedMatcher = signedPolicy?.recipientMatcher;
    if (typeof signedMatcher === "object" && signedMatcher !== null && !Array.isArray(signedMatcher)) {
      const value = signedMatcher as Record<string, unknown>;
      return value.kind === model.recipient.kind && value.value === model.recipient.value;
    }
    const recipientEmail = policy.recipientEmail;
    const matcherValue = model.recipient.kind === "emailDomain" ? `@${model.recipient.value}` : model.recipient.value;
    return typeof recipientEmail === "string" && ((model.recipient.kind === "emailDomain" && recipientEmail.toLowerCase().endsWith(String(matcherValue).toLowerCase())) || (model.recipient.kind !== "emailDomain" && recipientEmail === matcherValue));
  };
  const librarySource = contentSource(model.content);
  const candidate = capabilities.find((item) => item.source.kind === "kv" && (librarySource === undefined || item.source.space === librarySource.space && item.source.path === librarySource.path) && matcherMatches(item));
  if (candidate === undefined) throw fail("source", "no matching source capability was found");
  const publicKey = bytes((candidate.scope.signingCapability as Record<string, unknown>).publicKey, "signing public key");
  const rawTrustedNode = candidate.scope.trustedNode as Record<string, unknown>;
  const trustedNode = { ...rawTrustedNode, invitationPublicKey: bytes(rawTrustedNode.invitationPublicKey, "node invitation public key") };
  const scope: SenderScope = {
    ...candidate.scope,
    trustedNode,
    signingCapability: { capabilityId: candidate.capabilityId, publicKey },
    signer: {
      publicKey,
      async sign(input) {
        const idempotencyKey = toBase64Url(crypto.getRandomValues(new Uint8Array(16)));
        const signed = await fetch("/api/share/sign", { method: "POST", credentials: "include", cache: "no-store", redirect: "error", headers: { "content-type": "application/json", "idempotency-key": idempotencyKey }, body: JSON.stringify({ capabilityId: candidate.capabilityId, purpose: input.purpose, message: input.message, binding: input.binding }) });
        if (!signed.ok) throw fail("rejected", "share signing request was rejected");
        const result = await signed.json() as { readonly signature?: unknown };
        return bytes(result.signature, "signature");
      },
    },
  } as SenderScope;
  const source = librarySource ?? candidate.source;
  const config = await loadSharePublicConfig();
  const shareId = crypto.randomUUID();
  const selectedMatcher = model.recipient.kind === "exactEmail"
    ? { kind: "exactEmail" as const, value: model.recipient.value! }
    : { kind: "emailDomain" as const, value: model.recipient.value! };
  const scopeBoundary = scope.expiryMax ?? scope.expiresAt;
  // A domain share reuses the Node's already-signed policy, whose expiry is
  // fixed by that signature; only the authored (exact-email) path can carry
  // the sender's shorter choice. Either way the boundary clamps it.
  const expiresAt = model.recipient.kind === "emailDomain"
    ? scopeBoundary ?? model.expiresAt
    : clampExpiry(model.expiresAt, scopeBoundary);
  // Domain and folder cases are already issued as persisted, signed
  // capabilities by the authenticated Node. Reuse that policy/scope so the
  // enforcing boundary checks the stored domain or prefix claim directly;
  // exact-email shares still use the one-shot attenuation authoring path.
  const authored = model.recipient.kind === "emailDomain"
    ? { scope, policy: candidate.policy }
    : await authorAddressedDelegation({ scope, source, matcher: selectedMatcher, shareId, resource: model.resource, actions: model.permissions, expiresAt, fetchFn: options.fetchFn ?? globalThis.fetch });
  const delegatedScope = authored.scope;
  // Existing KV sources are already authenticated capabilities. Selecting one
  // must address that object/prefix; it must not overwrite it with the local
  // upload. Uploaded and pasted content use the same uploader and preserve bytes.
  if (model.encryption && model.content.kind !== "library") {
    if (file === undefined) throw fail("content", "encrypted addressed share has no file");
    const uploader = await createTinyCloudUploader(options.session!, config, [{ scope: delegatedScope, source, policy: authored.policy }], () => undefined, options.tinycloud);
    await uploader(file, { scope: delegatedScope, source, policy: authored.policy }, model.resource.path);
  }
  const v2 = true;
  const uploadEnvelope = async (cid: string, blob: Uint8Array, deleteAfter: string): Promise<void> => {
    const uploaded = await fetch(`${options.registryOrigin ?? options.origin}/api/share/link-only/registry/blobs`, { method: "POST", credentials: "include", cache: "no-store", redirect: "error", headers: { "content-type": "application/vnd.ipld.raw", "if-none-match": "*", "x-delete-after": deleteAfter }, body: blob as BodyInit });
    if (!uploaded.ok) throw fail("save", "addressed envelope upload was rejected");
    if (cid.length === 0) throw fail("internal", "addressed envelope CID is empty");
  };
  const publishBinding = async (binding: Record<string, unknown>): Promise<void> => {
    const published = await fetch("/api/share/bindings", { method: "POST", credentials: "include", cache: "no-store", redirect: "error", headers: { "content-type": "application/json" }, body: JSON.stringify({ capabilityId: candidate.capabilityId, shareCid: binding.shareCid, binding }) });
    if (!published.ok) throw fail("save", "share binding publish was rejected");
  };
  if (v2) {
    const authority = authored.policy;
    const policyBytes = strictBase64(authority.policyBytes, "Node policy bytes");
    const policyText = new TextDecoder("utf-8", { fatal: true }).decode(policyBytes);
    const policyValue = JSON.parse(policyText) as Record<string, unknown>;
    const policyKeys = ["type", "version", "issuerDid", "recipientMatcher", "contentSource", "contentSourceDigest", "resource", "actions", "expiresAt"];
    if (Object.keys(policyValue).some((key) => !policyKeys.includes(key)) || policyKeys.some((key) => !Object.hasOwn(policyValue, key)) || canonicalize(policyValue) !== policyText || policyValue.type !== "TinyCloudSharePolicy" || policyValue.issuerDid !== scope.senderDid) throw fail("internal", "addressed policy shape is invalid");
    const policyDigest = await digestBytes(policyBytes);
    if (policyDigest !== authority.policyDigest || await computeCid(policyBytes) !== authority.policyCid) throw fail("internal", "addressed policy digest does not match");
    const rawAuthorizedActions = (scope as unknown as Record<string, unknown>).actions;
    const authorizedActions: string[] = Array.isArray(rawAuthorizedActions) ? rawAuthorizedActions.filter((value: unknown): value is string => typeof value === "string") : [];
    const actionNames = [...new Set(model.permissions.flatMap((action) => action === "read" ? ["tinycloud.kv/get", "tinycloud.kv/metadata"] : action === "list" ? ["tinycloud.kv/list"] : ["tinycloud.kv/put"]))].sort();
    if (actionNames.some((action) => !authorizedActions.includes(action) && !authorizedActions.includes(action.replace("tinycloud.kv/", "")))) throw fail("permission", "requested actions exceed the sender's authorization");
    const policyMatcher = policyValue.recipientMatcher;
    const expectedMatcher = selectedMatcher;
    if (policyValue.version !== 2 || canonicalize(policyMatcher) !== canonicalize(expectedMatcher) || policyValue.contentSourceDigest !== await digestBytes(new TextEncoder().encode(canonicalize(source))) || policyValue.expiresAt !== expiresAt || canonicalize(policyValue.resource) !== canonicalize({ kind: model.resource.kind, value: model.resource.path.replace(/\/$/, "") }) || canonicalize(policyValue.contentSource) !== canonicalize(source) || canonicalize(policyValue.actions) !== canonicalize(actionNames)) throw fail("internal", "addressed policy binding does not match");
    const policy = { policyCid: authority.policyCid, policyBytes: authority.policyBytes, policyDigest: authority.policyDigest };
    const matcher = model.encryption ? selectedMatcher : { kind: "policyDigest" as const, value: policy.policyDigest };
    const deliveryEmail = model.deliveryEmail;
    if (deliveryEmail === undefined) throw fail("delivery", "addressed share has no delivery email");
    const bytes = file === undefined ? undefined : new Uint8Array(await file.arrayBuffer());
    const artifact = await createAddressedShareLink({
      matcher,
      deliveryEmail,
      source,
      scope: delegatedScope,
      policy,
      actions: model.permissions,
      resource: model.resource,
      shareId,
      expiresAt,
      filename: model.encryption ? contentFilename(model.content) : "",
      mediaType: model.encryption ? contentMediaType(model.content) : "application/octet-stream",
      byteLength: model.encryption ? bytes?.byteLength ?? 0 : 0,
      encrypted: model.encryption,
      format: model.linkFormat,
      uploadEnvelope,
      publishBinding,
    });
    return { url: artifact.shareUrl, cid: artifact.shareCid, format: model.linkFormat, expiresAt: artifact.expiresAt, notify: async () => {
      if (options.notify !== undefined) {
        await options.notify({ share: { url: artifact.shareUrl, cid: artifact.shareCid, format: model.linkFormat, expiresAt: artifact.expiresAt }, recipient: deliveryEmail, matcher: model.recipient.kind });
        return;
      }
      await sendShareEmail({ share: artifact, scope, adapters: createHttpTransport({ nodeOrigin: config.nodeOrigin, credentialsOrigin: config.credentialsOrigin }) });
    } };
  }
  const artifact = await createShareLink({ email: model.recipient.value!, source, scope, shareId: crypto.randomUUID(), expiresAt, policy: candidate.policy, adapters: {
    uploadEnvelope,
    publishBinding,
  } });
  return {
    url: artifact.shareUrl,
    cid: artifact.shareCid,
    format: model.linkFormat,
    expiresAt: artifact.expiresAt,
    notify: async () => {
      await sendShareEmail({
        share: artifact,
        scope,
        adapters: createHttpTransport({ nodeOrigin: config.nodeOrigin, credentialsOrigin: config.credentialsOrigin }),
      });
    },
  };
}

async function createOwnerPolicyShare(file: File | undefined, model: ShareComposerModel, options: ShareComposerOptions): Promise<ComposerShareResult> {
  const tinycloud = options.tinycloud;
  if (tinycloud === undefined) throw fail("session", "owner share has no TinyCloud session");
  const config = await loadSharePublicConfig();
  const spaceId = tinycloud.spaceId;
  if (spaceId === undefined || spaceId.length === 0) throw fail("storage", "owner share has no storage space");
  const shareId = crypto.randomUUID();
  const librarySource = contentSource(model.content);
  const selectedSource = librarySource?.kind === "kv" ? librarySource : undefined;
  const sourcePath = selectedSource?.path.replace(/\/+$/, "");
  const filename = contentFilename(model.content);
  if (filename.length === 0 || filename.includes("/") || filename === "." || filename === "..") throw fail("filename", "owner share filename is invalid");
  if (model.resource.kind === "prefix" && selectedSource === undefined) throw fail("folder", "owner prefix share has no selected library folder");
  const resourcePath = model.resource.kind === "prefix"
    ? `shares/${shareId}`
    : (model.resource.kind === "exact" && model.resource.path.startsWith("shares/") && selectedSource === undefined ? model.resource.path : `shares/${shareId}/${filename}`);
  if (resourcePath.length === 0 || resourcePath.endsWith("/") && model.resource.kind === "exact") throw fail("filename", "owner share resource filename is invalid");
  const resourceKind = selectedSource === undefined ? "exact" as const : model.resource.kind;
  const source = { kind: "kv" as const, space: spaceId, path: resourcePath, action: "tinycloud.kv/get" as const };
  const actionNames = [...new Set(model.permissions.flatMap((action) => action === "read" ? ["tinycloud.kv/get", "tinycloud.kv/metadata"] : action === "list" ? ["tinycloud.kv/list"] : ["tinycloud.kv/put"]))].sort() as OwnerSharePolicyV2["actions"];
  if (actionNames.length === 0) throw fail("actions", "owner share has no actions");
  // The sender chooses this in the composer (P1-2); it is no longer a hidden constant.
  const expiresAt = model.expiresAt;
  const matcher = model.recipient.kind === "exactEmail"
    ? { kind: "exactEmail" as const, value: model.recipient.value! }
    : { kind: "emailDomain" as const, value: model.recipient.value! };
  const deliveryEmail = model.deliveryEmail;
  const missingMethods = missingTinyCloudMethods(tinycloud, OWNER_TINYCLOUD_METHODS);
  if (missingMethods.length > 0) throw fail("internal", `the TinyCloud session does not provide the owner-share methods ${missingMethods.join(", ")}`, { missingTinyCloudMethods: missingMethods });
  const sdk = await ownerSdk();
  const shareKey = await sdk.createDelegatedShareKey({ extractable: false });
  try {
    if (selectedSource !== undefined && sourcePath !== undefined) {
      await copySelectedSource(tinycloud, spaceId, sourcePath, resourceKind, resourcePath);
    }
    const ownerDelegation = await tinycloud.createOwnerDelegation({ delegateDid: shareKey.did, spaceId, path: resourceKind === "prefix" ? `${resourcePath}/` : resourcePath, actions: actionNames, expiresAt: new Date(expiresAt) });
    const sourceDigest = await digestBytes(new TextEncoder().encode(canonicalize(source)));
    const policyValue: OwnerSharePolicyV2 = {
      type: "TinyCloudSharePolicy",
      version: 2,
      shareId,
      ownerDid: tinycloud.did,
      shareKeyDid: shareKey.did,
      recipientMatcher: matcher,
      target: { origin: config.nodeOrigin, nodeAudience: config.nodeAudience, enforcerDid: config.enforcerDid, spaceId },
      resource: { kind: resourceKind, path: resourcePath },
      actions: actionNames,
      contentSource: source,
      contentSourceDigest: sourceDigest,
      ownerDelegationCid: ownerDelegation.delegationCid,
      expiresAt,
    };
    const canonicalPolicy = await sdk.canonicalOwnerSharePolicy(policyValue);
    const policyProof = toBase64Url(await shareKey.sign(canonicalPolicy.bytes));
    const enforcementDelegation = await sdk.createPolicyEnforcementDelegation({ ownerDelegation, shareKey, enforcerDid: config.enforcerDid, policyCid: canonicalPolicy.cid, shareId, spaceId, nodeAudience: config.nodeAudience, path: resourcePath, actions: actionNames, contentSourceDigest: sourceDigest, expiresAt });
    // The registration receipt is signed by the enrolled Node key. The trust
    // bundle pins both its kid and public key before the exact response bytes
    // are accepted by the SDK.
    const registration = await tinycloud.registerOwnerSharePolicy({ policy: { bytes: canonicalPolicy.bytes, cid: canonicalPolicy.cid, proof: policyProof }, ownerDelegation, enforcementDelegation, contentSourceDigest: sourceDigest, nodeProof: { kid: config.nodeInvitationKid, publicKey: fromBase64Url(config.nodeInvitationPublicKey) } });
    const authorityMaterialDigest = await digestBytes(fromBase64Url(enforcementDelegation.dagCbor));
    const envelopeIdentity = { schema: "xyz.tinycloud.share/envelope/v2", version: 2, shareId, delegationCid: ownerDelegation.delegationCid, policyCid: canonicalPolicy.cid, target: { origin: config.nodeOrigin, nodeAudience: config.nodeAudience, enforcerDid: config.enforcerDid, spaceId }, resource: { kind: resourceKind, path: resourcePath }, actions: actionNames, contentSource: source, contentSourceDigest: sourceDigest, expiresAt };
    const envelopeCid = await computeCid(new TextEncoder().encode(canonicalize(envelopeIdentity)));
    const shareCid = await computeCid(new TextEncoder().encode(canonicalize({ version: 2, shareId, policyCid: canonicalPolicy.cid, envelopeCid })));
    const outerUnsigned = {
      schema: "xyz.tinycloud.share/envelope/v2",
      version: 2,
      envelopeCid,
      shareCid,
      shareId,
      delegationCid: ownerDelegation.delegationCid,
      policyCid: canonicalPolicy.cid,
      target: { origin: config.nodeOrigin, nodeAudience: config.nodeAudience, enforcerDid: config.enforcerDid, spaceId },
      resource: { kind: resourceKind, path: resourcePath },
      actions: actionNames,
      contentSource: source,
      contentSourceDigest: sourceDigest,
      expiresAt,
    };
    const outerSignature = toBase64Url(await shareKey.sign(new TextEncoder().encode(`xyz.tinycloud.share/envelope/v2\0${canonicalize(outerUnsigned)}`)));
    const ownerAuthority = { registrationCid: registration.registration.registrationCid, shareCid, envelopeCid, enforcementDelegation, outerEnvelope: { ...outerUnsigned, signature: { signerDid: shareKey.did, algorithm: "Ed25519", value: outerSignature } } };
    const unsigned = { version: 2 as const, shareId, recipientMatcher: matcher, ...(deliveryEmail === undefined ? {} : { deliveryEmail }), actions: model.permissions, resource: { kind: resourceKind, path: resourcePath }, target: { origin: config.nodeOrigin, nodeAudience: config.nodeAudience, spaceId }, delegationCid: ownerDelegation.delegationCid, authorityMaterialHandle: registration.registration.registrationCid, authorityMaterialDigest, contentSource: source, contentSourceDigest: sourceDigest, authorizationTarget: { kind: "policy" as const, policyCid: canonicalPolicy.cid, policyBytes: toBase64Url(canonicalPolicy.bytes) }, display: model.encryption ? { filename } : {}, expiry: expiresAt, encrypted: true, metadata: { mediaType: contentMediaType(model.content), byteLength: file?.size ?? 0, filename }, ownerAuthority };
    // The signature covers `unsigned`, so `unsigned` must be checked with the
    // unsigned schema; `shareEnvelopeV2Schema` requires `signature` and so
    // always threw "signature Required" here (TC-338). The signed envelope is
    // then checked with the schema recipients actually parse, so the envelope
    // this browser emits is rejected here rather than at the viewer.
    unsignedShareEnvelopeV2Schema.parse(unsigned);
    const envelopeSignature = toBase64Url(await shareKey.sign(new TextEncoder().encode(`xyz.tinycloud.share/envelope/v2\0${canonicalize(unsigned)}`)));
    const signedEnvelope = { ...unsigned, signature: { signerDid: shareKey.did, algorithm: "Ed25519", value: envelopeSignature } };
    shareEnvelopeV2Schema.parse(signedEnvelope);
    const envelopeBytes = new TextEncoder().encode(canonicalize(signedEnvelope));
    const key = model.encryption ? generateKey() : undefined;
    const stored = key === undefined ? { cid: await computeCid(envelopeBytes), blob: envelopeBytes } : await seal(envelopeBytes, key);
    if (key === undefined) throw fail("internal", "owner share encryption key is missing");
    const shareUrl = model.linkFormat === "inline"
      ? await encodeInlineShareUrl({ origin: config.shareOrigin, ciphertext: stored.blob, key32: key })
      : (await (async () => { const uploaded = await fetch(`${options.registryOrigin ?? config.registryOrigin}/api/share/link-only/registry/blobs`, { method: "POST", credentials: "omit", cache: "no-store", redirect: "error", headers: { "content-type": "application/vnd.ipld.raw", "if-none-match": "*", "x-delete-after": expiresAt }, body: stored.blob as BodyInit }); if (!uploaded.ok) throw fail("save", "owner envelope upload was rejected"); return encodeShareUrl({ origin: config.shareOrigin, ciphertextCid: stored.cid, key32: key }); })());
    key.fill(0);
    if (selectedSource === undefined && model.content.kind !== "library") {
      if (file === undefined) throw fail("content", "owner upload has no file");
      const content = new Uint8Array(await file.arrayBuffer());
      const result = await tinycloud.kvForSpace(spaceId).put(resourcePath, content, { contentType: contentMediaType(model.content) });
      if (!result.ok) throw fail("upload", "owner file upload was rejected");
    }
    return { url: shareUrl, cid: stored.cid, format: model.linkFormat, expiresAt, delegationCid: ownerDelegation.delegationCid, ...(deliveryEmail === undefined ? {} : { notify: async () => {
      const share = { url: shareUrl, cid: stored.cid, format: model.linkFormat, expiresAt } as ComposerShareResult;
      if (missingTinyCloudMethods(tinycloud, OWNER_TINYCLOUD_DELIVERY_METHODS).length > 0) throw new Error("We couldn't send that email. The link above still works.");
      // Called as a method, not as a detached function: the SDK implementation
      // reads `this`. `nodeProof` and `credentialsAudience` are required — the
      // SDK verifies the Node's detached EdDSA proof over the exact response
      // bytes and pins the witness the delivery is scoped to. The previous
      // `(input: Record<string, string>)` cast erased both from the compiler's
      // view, so the omission only showed up at runtime (TC-343).
      const deliveryAuthorization = await tinycloud.authorizeShareDelivery({ envelopeCid, shareCid, shareId, registrationCid: registration.registration.registrationCid, policyCid: canonicalPolicy.cid, delegationCid: ownerDelegation.delegationCid, enforcementDelegationCid: enforcementDelegation.cid, resourcePath, recipientEmail: deliveryEmail, shareUrl: share.url, documentName: filename, expiresAt: new Date(Math.min(Date.parse(expiresAt), Date.now() + 5 * 60 * 1000)).toISOString(), nodeProof: { kid: config.nodeInvitationKid, publicKey: fromBase64Url(config.nodeInvitationPublicKey) }, credentialsAudience: config.credentialsOrigin });
      if (options.notify === undefined) throw new Error("We couldn't send that email. The link above still works.");
      await options.notify({ share, recipient: deliveryEmail, matcher: model.recipient.kind, deliveryAuthorization });
    } }) };
  } finally {
    shareKey.clear();
  }
}

export async function copySelectedSource(
  tinycloud: ShareTinyCloud,
  spaceId: string,
  sourcePath: string,
  resourceKind: "exact" | "prefix",
  targetPath: string,
): Promise<void> {
  const kv = tinycloud.kvForSpace(spaceId);
  if (resourceKind === "exact") {
    const result = await kv.get<Uint8Array>(sourcePath, { binary: true });
    if (!result.ok) throw fail("libraryCopy", "library file read failed during copy");
    const stored = await kv.put(targetPath, result.data.data, { contentType: result.data.headers.contentType ?? "application/octet-stream" });
    if (!stored.ok) throw fail("libraryCopy", "library file write failed during copy");
    return;
  }
  const listing = await kv.list({ path: sourcePath, limit: 1000 });
  if (!listing.ok) throw fail("libraryOpen", "library folder listing failed");
  const prefix = `${sourcePath}/`;
  const directChildren = listing.data.keys.filter((candidate) => {
    if (!candidate.startsWith(prefix)) return false;
    const remainder = candidate.slice(prefix.length);
    return remainder.length > 0 && !remainder.includes("/");
  });
  for (const childPath of directChildren) {
    const result = await kv.get<Uint8Array>(childPath, { binary: true });
    if (!result.ok) throw fail("libraryCopy", "library folder child read failed during copy");
    const childName = childPath.slice(prefix.length);
    const stored = await kv.put(`${targetPath}/${childName}`, result.data.data, { contentType: result.data.headers.contentType ?? "application/octet-stream" });
    if (!stored.ok) throw fail("libraryCopy", "library folder child write failed during copy");
  }
}

async function authorAddressedDelegation(input: { readonly scope: SenderScope; readonly source: ContentSource; readonly matcher: { readonly kind: "exactEmail" | "emailDomain"; readonly value: string }; readonly shareId: string; readonly resource: ShareComposerModel["resource"]; readonly actions: readonly SharePermission[]; readonly expiresAt: string; readonly fetchFn: typeof fetch }): Promise<{ readonly scope: SenderScope; readonly policy: { readonly policyCid: string; readonly policyBytes: string; readonly policyDigest: string } }> {
  if (input.scope.delegation.length === 0 || input.scope.delegationCid.length === 0 || input.scope.authorityMaterialHandle.length === 0 || input.scope.authorityMaterialDigest.length === 0) throw fail("internal", "addressed authoring scope is incomplete");
  const actions = [...new Set(input.actions.flatMap((action) => action === "read" ? ["tinycloud.kv/get", "tinycloud.kv/metadata"] : action === "list" ? ["tinycloud.kv/list"] : ["tinycloud.kv/put"]))].sort();
  const resource = { kind: input.resource.kind, value: input.resource.path.replace(/\/$/, "") } as const;
  const requestBody = { version: 2, nonce: toBase64Url(crypto.getRandomValues(new Uint8Array(32))), jti: toBase64Url(crypto.getRandomValues(new Uint8Array(16))), senderDid: input.scope.senderDid, recipientMatcher: input.matcher, targetOrigin: input.scope.targetOrigin, nodeAudience: input.scope.nodeAudience, shareCid: input.scope.delegationCid, shareId: input.shareId, delegationCid: input.scope.delegationCid, authorityMaterialHandle: input.scope.authorityMaterialHandle, authorityMaterialDigest: input.scope.authorityMaterialDigest, contentSource: input.source, contentSourceDigest: await canonicalDigest(input.source), actions, resource, expiresAt: input.expiresAt };
  const request = { ...requestBody, requestBodyDigest: await canonicalDigest(requestBody) };
  const signature = await input.scope.signer.sign({ purpose: "delegationAuthoring", message: canonicalize(request), binding: request });
  const signerDid = didKeyFromEd25519PublicKey(input.scope.signingCapability.publicKey);
  if (signerDid !== input.scope.senderDid || input.scope.signer.publicKey.length !== 32) throw fail("internal", "addressed authoring signer does not match sender");
  const proof = { alg: "EdDSA", kid: `${signerDid}#${signerDid.slice("did:key:".length)}`, signature: toBase64Url(signature) };
  const response = await input.fetchFn(new URL("/delegate", input.scope.targetOrigin), { method: "POST", credentials: "omit", redirect: "error", headers: { accept: "application/json", "content-type": "application/vnd.tinycloud.delegation+json" }, body: JSON.stringify({ request, proof }) });
  if (!response.ok) {
    let code: unknown;
    try {
      const error = await response.clone().json() as { readonly error?: { readonly code?: unknown } | unknown };
      const value = error.error;
      code = typeof value === "object" && value !== null && "code" in value ? value.code : undefined;
    } catch { /* Keep the user-facing error independent of an upstream response body. */ }
    throw fail("rejected", "delegation authoring request was rejected", { code, status: response.status });
  }
  const value = await response.json() as Record<string, unknown>;
  const required = ["type", "version", "nonce", "jti", "policyCid", "policyBytes", "policyDigest", "delegationCid", "delegationBytes", "delegationDigest", "authorityMaterialHandle", "authorityMaterialDigest", "actions", "resource", "expiresAt", "proof"];
  if (Object.keys(value).some((key) => !required.includes(key)) || required.some((key) => !Object.hasOwn(value, key)) || value.type !== "TinyCloudShareAddressedDelegation" || value.version !== 2 || value.nonce !== request.nonce || value.jti !== request.jti || typeof value.policyCid !== "string" || typeof value.policyBytes !== "string" || typeof value.policyDigest !== "string" || typeof value.delegationCid !== "string" || typeof value.delegationBytes !== "string" || typeof value.delegationDigest !== "string" || !Array.isArray(value.actions) || typeof value.expiresAt !== "string") throw fail("internal", "delegation authoring response shape is invalid");
  const responseProof = value.proof as Record<string, unknown>;
  if (typeof responseProof !== "object" || responseProof === null || Array.isArray(responseProof) || Object.keys(responseProof).sort().join(",") !== "alg,kid,signature" || responseProof.alg !== "EdDSA" || typeof responseProof.kid !== "string" || typeof responseProof.signature !== "string") throw fail("internal", "delegation authoring response proof is invalid");
  const signedResponse = { ...value }; delete signedResponse.proof;
  await verifyNodeProof(signedResponse, responseProof as never, input.scope.trustedNode, "xyz.tinycloud.share/delegation-authoring-response/v2\0");
  const responsePolicyBytes = strictBase64(String(value.policyBytes), "Node policy bytes");
  const responseDelegationBytes = strictBase64(String(value.delegationBytes), "Node delegation bytes");
  if (value.authorityMaterialHandle !== input.scope.authorityMaterialHandle || value.authorityMaterialDigest !== input.scope.authorityMaterialDigest || canonicalize(value.actions) !== canonicalize(actions) || canonicalize(value.resource) !== canonicalize(resource) || value.expiresAt !== input.expiresAt || await digestBytes(responsePolicyBytes) !== value.policyDigest || await computeCid(responsePolicyBytes) !== value.policyCid || await digestBytes(responseDelegationBytes) !== value.delegationDigest) throw fail("internal", "delegation authoring response binding does not match");
  return { scope: { ...input.scope, delegation: String(value.delegationBytes), delegationCid: String(value.delegationCid) }, policy: { policyCid: String(value.policyCid), policyBytes: String(value.policyBytes), policyDigest: String(value.policyDigest) } };
}

function strictBase64(value: string, label: string): Uint8Array {
  let decoded: Uint8Array;
  try { decoded = fromBase64Url(value); } catch { throw fail("internal", `${label} is invalid`); }
  if (decoded.length === 0 || toBase64Url(decoded) !== value) throw fail("internal", `${label} is invalid`);
  return decoded;
}

function recipientModel(kind: RecipientKind, value: string): ShareComposerModel["recipient"] {
  if (kind === "bearer") return { kind };
  return { kind, value: kind === "emailDomain" ? normalizeEmailDomain(value) : normalizeEmail(value) };
}

/** Only one mounted composer owns the document-level paste fallback. */
let composerPasteScope: AbortController | undefined;

function formatBytes(size: number): string {
  return size < 1024 ? `${size} B` : `${(size / 1024).toFixed(1)} KB`;
}

function shortDate(iso: string): string {
  return new Date(iso).toLocaleDateString(undefined, { month: "short", day: "numeric" });
}

export function mountShareComposer(root: HTMLElement, options: ShareComposerOptions): void {
  const doc = root.ownerDocument;
  const copyText = options.copyText ?? copyWithFallback;
  const defaults = defaultComposerModel();
  root.removeAttribute("aria-busy");
  root.replaceChildren();

  const shell = el(doc, "main", "sender-shell composer-shell");
  // Every terminal screen keeps a visible way home (P0-1).
  const back = el(doc, "button", "button button-ghost composer-back", "← All shares") as HTMLButtonElement;
  back.type = "button";
  back.addEventListener("click", () => options.onBack());
  const header = el(doc, "header", "sender-header");
  const shortAddress = options.openKeyAddress.length > 12 ? `${options.openKeyAddress.slice(0, 6)}…${options.openKeyAddress.slice(-4)}` : options.openKeyAddress;
  header.append(el(doc, "p", "sender-kicker", `Signed in · ${shortAddress}`), el(doc, "h1", "sender-title", "Share a file"), el(doc, "p", "sender-lede", "Encrypted in your browser. You get a private link — we never send it for you unless you ask."));

  const form = el(doc, "form", "sender-form composer-form") as HTMLFormElement;
  form.noValidate = true;
  const progress = el(doc, "ol", "share-progress");
  progress.setAttribute("aria-label", "Sharing steps");
  for (const [number, label, state] of [["01", "Choose", "current"], ["02", "Set access", "upcoming"], ["03", "Copy or send", "upcoming"]] as const) {
    const item = el(doc, "li", ""); item.dataset.state = state; item.append(el(doc, "span", "", number), doc.createTextNode(label)); progress.append(item);
  }

  // What to share. One target, four ways in: click, drag, paste, library.
  // The kind of content is inferred from what the sender did (P1-1).
  const contentSection = el(doc, "section", "composer-section content-section");
  const drop = el(doc, "div", "content-dropzone");
  drop.tabIndex = 0;
  drop.setAttribute("role", "button");
  drop.setAttribute("aria-label", "Choose a file to share, or paste text");
  const dropTitle = el(doc, "strong", "dropzone-title", "Drop a file here, or click to choose");
  const dropHint = el(doc, "span", "dropzone-hint", "You can also paste text or an image");
  const dropLimit = el(doc, "span", "dropzone-limit", "Up to 100 MB");
  const fileInput = el(doc, "input", "upload-input") as HTMLInputElement;
  fileInput.type = "file"; fileInput.name = "document"; fileInput.accept = "*/*";
  const libraryLink = el(doc, "button", "dropzone-library", "or pick from your library") as HTMLButtonElement;
  libraryLink.type = "button";
  drop.append(dropTitle, dropHint, dropLimit, fileInput, libraryLink);

  const chosen = el(doc, "div", "content-chosen"); chosen.hidden = true;
  const chosenName = el(doc, "strong", "content-chosen-name");
  const chosenMeta = el(doc, "span", "content-chosen-meta");
  const change = el(doc, "button", "button button-secondary content-change", "Change") as HTMLButtonElement; change.type = "button";
  chosen.append(chosenName, chosenMeta, change);

  const textPanel = el(doc, "div", "content-text"); textPanel.hidden = true;
  const nameChip = el(doc, "input", "field-input content-filename") as HTMLInputElement;
  nameChip.type = "text"; nameChip.name = "content-filename"; nameChip.setAttribute("aria-label", "Name this text");
  const author = el(doc, "textarea", "field-input author-input") as HTMLTextAreaElement;
  author.name = "author-content"; author.rows = 8; author.setAttribute("aria-label", "Text to share");
  const useFile = el(doc, "button", "dropzone-library use-file-instead", "Use a file instead") as HTMLButtonElement; useFile.type = "button";
  textPanel.append(nameChip, author, useFile);

  const libraryPanel = el(doc, "div", "content-library"); libraryPanel.hidden = true;
  const sourceLabel = el(doc, "label", "field-label source-field", "From your library");
  const source = el(doc, "select", "field-input") as HTMLSelectElement; source.name = "kv-source";
  sourceLabel.append(source);
  const useUpload = el(doc, "button", "dropzone-library use-file-instead", "Share something else instead") as HTMLButtonElement; useUpload.type = "button";
  libraryPanel.append(sourceLabel, useUpload);
  contentSection.append(drop, chosen, textPanel, libraryPanel);

  // Who can open it. The third recipient kind lives in Advanced.
  const fieldset = el(doc, "fieldset", "composer-section recipient-section");
  fieldset.append(el(doc, "legend", "field-legend", "Who can open it"));
  const recipientInput = el(doc, "input", "field-input recipient-value") as HTMLInputElement;
  const addRecipientOption = (parent: HTMLElement, kind: RecipientKind, copy: string): void => {
    const labelNode = el(doc, "label", "recipient-option");
    const radio = el(doc, "input", "") as HTMLInputElement;
    radio.type = "radio"; radio.name = "recipient"; radio.value = kind; radio.checked = kind === defaults.recipient.kind;
    labelNode.append(radio, el(doc, "span", "recipient-option-copy", copy));
    parent.append(labelNode);
  };
  addRecipientOption(fieldset, "exactEmail", "Only this person — they'll confirm their email to open it");
  addRecipientOption(fieldset, "bearer", "Anyone with the link — anyone you send it to can open it");
  recipientInput.type = "text"; recipientInput.name = "recipient-value"; recipientInput.placeholder = "name@example.com"; recipientInput.autocomplete = "email"; recipientInput.hidden = true; recipientInput.setAttribute("aria-label", "Recipient email or domain");
  fieldset.append(recipientInput);

  // When it stops working. The sender was never asked before (P1-2).
  const expiryLabel = el(doc, "label", "field-label expiry-field", "Link expires");
  const expiry = el(doc, "select", "field-input") as HTMLSelectElement; expiry.name = "expiry";
  for (const [value, label] of EXPIRY_CHOICES) { const option = el(doc, "option", "", label) as HTMLOptionElement; option.value = value; expiry.append(option); }
  expiry.value = DEFAULT_EXPIRY_CHOICE;
  expiryLabel.append(expiry);

  const accessFieldset = el(doc, "fieldset", "composer-section access-section");
  accessFieldset.append(el(doc, "legend", "field-legend", "What can they do?"));
  const accessControls: Array<{ readonly value: SharePermission; readonly label: HTMLLabelElement; readonly input: HTMLInputElement }> = [];
  for (const [value, label] of [["read", "Can view — open and download"], ["list", "Can browse the folder"], ["edit", "Can edit — open, download, and save changes"]] as const) {
    const labelNode = el(doc, "label", "permission-option"); const input = el(doc, "input", "") as HTMLInputElement; input.type = "checkbox"; input.name = "permission"; input.value = value; input.checked = value === "read"; labelNode.append(input, el(doc, "span", "permission-copy", label)); accessControls.push({ value, label: labelNode, input }); accessFieldset.append(labelNode);
  }
  const accessHint = el(doc, "p", "scope-note composer-access-hint", "Link-only shares are view-only. Choose a specific person to allow editing.");
  accessHint.hidden = true;
  accessFieldset.append(accessHint);

  // Advanced. Everything that is a default, not a question.
  const advanced = el(doc, "details", "composer-advanced");
  advanced.append(el(doc, "summary", "composer-advanced-summary", "Advanced settings"));
  const formatLabel = el(doc, "label", "field-label", "Link style"); const format = el(doc, "select", "field-input") as HTMLSelectElement; format.name = "format"; for (const [value, label] of [["compact", "Short link (recommended)"], ["inline", "Self-contained link — very long, works without our servers"]] as const) { const option = el(doc, "option", "", label) as HTMLOptionElement; option.value = value; format.append(option); } formatLabel.append(format);
  const domainGroup = el(doc, "div", "advanced-recipient");
  addRecipientOption(domainGroup, "emailDomain", "Anyone at a company — anyone with an email at this domain");
  const encryptionGroup = el(doc, "div", "encryption-group"); encryptionGroup.hidden = true;
  const encryptionLabel = el(doc, "label", "toggle-option"); const encryption = el(doc, "input", "") as HTMLInputElement; encryption.type = "checkbox"; encryption.name = "encryption"; encryption.checked = true; encryptionLabel.append(encryption, el(doc, "span", "", "Hide the file name and recipient from our servers"));
  const warningLabel = el(doc, "label", "toggle-option encryption-warning"); const warning = el(doc, "input", "") as HTMLInputElement; warning.type = "checkbox"; warning.name = "encryption-acknowledgment"; warningLabel.append(warning, el(doc, "span", "", "I understand the file name and recipient domain will be visible to our servers")); warningLabel.hidden = true;
  encryptionGroup.append(encryptionLabel, warningLabel);
  const deliveryLabel = el(doc, "label", "field-label delivery-field", "Send the email somewhere else (optional)"); const delivery = el(doc, "input", "field-input delivery-value") as HTMLInputElement; delivery.type = "email"; delivery.name = "delivery-email"; deliveryLabel.append(delivery); deliveryLabel.hidden = true;
  const saveAsLabel = el(doc, "label", "field-label save-as-field", "Save it as"); const saveAs = el(doc, "input", "field-input") as HTMLInputElement; saveAs.type = "text"; saveAs.name = "save-as"; saveAs.autocomplete = "off"; saveAsLabel.append(saveAs);
  advanced.append(formatLabel, domainGroup, encryptionGroup, deliveryLabel, saveAsLabel);

  const note = el(doc, "p", "scope-note composer-note");
  const submit = el(doc, "button", "button button-primary create-link-button", "Create link"); submit.type = "submit";
  const status = el(doc, "div", "sender-status composer-status"); status.setAttribute("aria-live", "polite"); status.setAttribute("aria-atomic", "true");
  form.append(progress, contentSection, fieldset, expiryLabel, accessFieldset, advanced, note, submit, status); shell.append(back, header, form); root.append(shell);

  let created: ComposerShareResult | undefined;
  let availableCapabilities: readonly { readonly capabilityId: string; readonly scope: Record<string, unknown>; readonly source: ContentSource; readonly policy: SenderPolicy }[] = [];
  // The tag mirrors the ComposerContent union: it records what the sender did,
  // it is never a control the sender has to operate.
  let contentKind: "empty" | "file" | "text" | "library" = "empty";
  let chosenFile: File | undefined;
  let deliveryTouched = false;

  const selectedKind = (): RecipientKind => (form.querySelector<HTMLInputElement>("input[name=recipient]:checked")?.value ?? "bearer") as RecipientKind;
  const signedMatcher = (candidate: { readonly policy: SenderPolicy }): { readonly kind: RecipientKind; readonly value: string } | undefined => {
    const policy = candidate.policy as unknown as Record<string, unknown>;
    if (typeof policy.policyBytes !== "string") return undefined;
    try {
      const parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(fromBase64Url(policy.policyBytes))) as unknown;
      if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return undefined;
      const matcher = (parsed as Record<string, unknown>).recipientMatcher;
      if (typeof matcher !== "object" || matcher === null || Array.isArray(matcher)) return undefined;
      const value = matcher as Record<string, unknown>;
      if ((value.kind !== "exactEmail" && value.kind !== "emailDomain") || typeof value.value !== "string") return undefined;
      return { kind: value.kind, value: value.value };
    } catch { return undefined; }
  };
  const selectRecipientCapability = (): void => {
    const kind = selectedKind();
    if (kind === "bearer" || availableCapabilities.length === 0 || recipientInput.value.length === 0) return;
    const value = kind === "emailDomain" ? normalizeEmailDomain(recipientInput.value) : normalizeEmail(recipientInput.value);
    const match = availableCapabilities.find((candidate) => {
      if (candidate.source.kind !== "kv") return false;
      const matcher = signedMatcher(candidate);
      return matcher?.kind === kind && matcher.value === value;
    });
    if (match === undefined) return;
    const index = Array.from(source.options).findIndex((option) => option.dataset.capabilityId === match.capabilityId);
    if (index >= 0 && source.selectedIndex !== index) { source.selectedIndex = index; source.dispatchEvent(new Event("change", { bubbles: true })); }
  };

  const expiryIso = (): string => expiryFromChoice(expiry.value as ExpiryChoice);
  const refreshNote = (): void => {
    const kind = selectedKind();
    const typed = recipientInput.value.trim();
    note.textContent = kind === "bearer"
      ? `Anyone who gets this link can open it. It can't be revoked early — it stops working on ${shortDate(expiryIso())}.`
      : kind === "emailDomain"
        ? `Anyone with an @${typed.length === 0 ? "example.com" : typed} email can open this after confirming their address.`
        : `Only ${typed.length === 0 ? "that person" : typed} can open this. Creating the link doesn't email them — you'll get that option next.`;
  };
  const refreshRecipient = (): void => {
    const kind = selectedKind(); const addressed = kind !== "bearer";
    recipientInput.hidden = !addressed; deliveryLabel.hidden = !addressed;
    for (const control of accessControls) {
      if (control.value === "read") {
        if (!addressed) control.input.checked = true;
        control.input.disabled = !addressed;
      } else {
        control.label.hidden = !addressed;
        if (!addressed) control.input.checked = false;
      }
    }
    accessHint.hidden = addressed;
    if (!addressed) { delivery.value = ""; deliveryTouched = false; }
    recipientInput.type = kind === "emailDomain" ? "text" : "email"; recipientInput.placeholder = kind === "emailDomain" ? "example.com" : "name@example.com";
    // Encryption is a real choice only for domain shares; everywhere else it
    // is required, so the control is not shown at all (P1-4).
    encryptionGroup.hidden = kind !== "emailDomain";
    if (kind !== "emailDomain") encryption.checked = true;
    if (kind === "emailDomain" && !encryption.checked) format.value = "inline";
    warningLabel.hidden = kind !== "emailDomain" || encryption.checked;
    if (warningLabel.hidden) warning.checked = false;
    // The authorized mailbox is the natural delivery address.
    if (kind === "exactEmail" && !deliveryTouched) delivery.value = recipientInput.value.trim();
    refreshNote();
    if (addressed) { try { selectRecipientCapability(); } catch { /* submit reports invalid recipient input */ } }
  };
  form.querySelectorAll<HTMLInputElement>("input[name=recipient]").forEach((input) => input.addEventListener("change", refreshRecipient));
  recipientInput.addEventListener("input", refreshRecipient);
  encryption.addEventListener("change", refreshRecipient);
  expiry.addEventListener("change", refreshNote);
  delivery.addEventListener("input", () => { deliveryTouched = true; });
  refreshRecipient();

  const showDropzone = (): void => {
    contentKind = "empty"; chosenFile = undefined; fileInput.value = "";
    chosen.hidden = true; textPanel.hidden = true; libraryPanel.hidden = true; drop.hidden = false; drop.dataset.over = "false";
  };
  const chooseFile = (file: File): void => {
    contentKind = "file"; chosenFile = file;
    drop.hidden = true; textPanel.hidden = true; libraryPanel.hidden = true;
    chosen.hidden = false; chosenName.textContent = file.name; chosenMeta.textContent = formatBytes(file.size);
  };
  const chooseText = (text: string): void => {
    contentKind = "text"; chosenFile = undefined;
    drop.hidden = true; chosen.hidden = true; libraryPanel.hidden = true; textPanel.hidden = false;
    author.value = text; nameChip.value = modelFilename(text);
  };
  const chooseLibrary = (): void => {
    contentKind = "library"; chosenFile = undefined;
    drop.hidden = true; chosen.hidden = true; textPanel.hidden = true; libraryPanel.hidden = false;
  };
  const handlePaste = (event: ClipboardEvent): void => {
    const data = event.clipboardData;
    if (data === null || data === undefined) return;
    const pastedFile = data.files.length > 0 ? data.files[0] : undefined;
    if (pastedFile !== undefined) { event.preventDefault(); chooseFile(pastedFile); return; }
    const text = data.getData("text/plain");
    if (text.length === 0) return;
    event.preventDefault();
    chooseText(text);
  };
  drop.addEventListener("click", (event) => {
    const target = event.target;
    if (target === fileInput || target === libraryLink) return;
    fileInput.click();
  });
  drop.addEventListener("keydown", (event) => {
    if (event.target !== drop || (event.key !== "Enter" && event.key !== " ")) return;
    event.preventDefault(); fileInput.click();
  });
  drop.addEventListener("dragover", (event) => { event.preventDefault(); drop.dataset.over = "true"; });
  drop.addEventListener("dragleave", () => { drop.dataset.over = "false"; });
  drop.addEventListener("drop", (event) => {
    event.preventDefault(); drop.dataset.over = "false";
    const dropped = event.dataTransfer?.files?.[0];
    if (dropped !== undefined) chooseFile(dropped);
  });
  drop.addEventListener("paste", handlePaste);
  composerPasteScope?.abort();
  const pasteScope = new AbortController();
  composerPasteScope = pasteScope;
  doc.addEventListener("paste", (event) => {
    if (contentKind !== "empty" || !form.isConnected) return;
    const target = event.target;
    if (target instanceof HTMLInputElement || target instanceof HTMLTextAreaElement || target instanceof HTMLSelectElement) return;
    handlePaste(event);
  }, { signal: pasteScope.signal });
  fileInput.addEventListener("change", () => { const picked = fileInput.files?.[0]; if (picked !== undefined) chooseFile(picked); });
  libraryLink.addEventListener("click", chooseLibrary);
  change.addEventListener("click", () => { showDropzone(); drop.focus(); });
  useFile.addEventListener("click", () => { showDropzone(); drop.focus(); });
  useUpload.addEventListener("click", () => { showDropzone(); drop.focus(); });

  void (options.loadCapabilities === undefined ? fetch("/api/share/capabilities", { credentials: "include", cache: "no-store", redirect: "error" }).then(async (response) => response.ok ? ((await response.json()) as { readonly capabilities?: readonly { readonly capabilityId: string; readonly scope: Record<string, unknown>; readonly source: ContentSource; readonly policy: SenderPolicy }[] }).capabilities ?? [] : []) : options.loadCapabilities()).then((capabilities) => {
    availableCapabilities = capabilities;
    for (const candidate of capabilities) {
      if (candidate.source.kind !== "kv") continue;
      const add = (path: string, kind: "exact" | "prefix"): void => {
        const canonical = kind === "prefix" ? (path.endsWith("/") ? path : `${path}/`) : path.replace(/\/$/, "");
        if (canonical.length === 0 || /(^|\/)(?:\.|\.\.)($|\/)/.test(canonical) || /[\u0000-\u001f\u007f\\]/.test(canonical)) return;
        const readable = canonical.split("/").filter(Boolean).at(-1) ?? canonical;
        const option = el(doc, "option", "", kind === "prefix" ? `${readable}/ (folder)` : readable) as HTMLOptionElement;
        option.value = canonical; option.dataset.space = candidate.source.space; option.dataset.resourceKind = kind; option.dataset.capabilityId = candidate.capabilityId;
        const matcher = signedMatcher(candidate); if (matcher !== undefined) { option.dataset.recipientMatcherKind = matcher.kind; option.dataset.recipientMatcherValue = matcher.value; }
        source.append(option);
      };
      add(candidate.source.path, candidate.source.path.endsWith("/") ? "prefix" : "exact");
      const prefixes = candidate.scope.prefixes;
      if (Array.isArray(prefixes)) for (const prefix of prefixes) if (typeof prefix === "string") add(prefix, "prefix");
      const resources = candidate.scope.resources;
      if (Array.isArray(resources)) for (const resource of resources) if (typeof resource === "object" && resource !== null) { const value = resource as Record<string, unknown>; if (typeof value.path === "string" && (value.kind === "exact" || value.kind === "prefix")) add(value.path, value.kind); }
    }
    try { selectRecipientCapability(); } catch { /* submit reports invalid recipient input */ }
  }).catch(() => undefined);

  form.addEventListener("submit", (event) => {
    event.preventDefault();
    void (async () => {
      const kind = selectedKind();
      try {
        const selectedOption = source.selectedOptions[0];
        const fallbackCapability = availableCapabilities.find((candidate) => candidate.source.kind === "kv" && Array.isArray(candidate.scope.prefixes) && candidate.scope.prefixes.some((prefix) => typeof prefix === "string"));
        const fallbackPrefixes = Array.isArray(fallbackCapability?.scope.prefixes) ? fallbackCapability.scope.prefixes.filter((prefix): prefix is string => typeof prefix === "string") : [];
        const fallbackPrefix = fallbackPrefixes[0];
        // A caller may set a select's value before async capabilities finish
        // populating its options (the browser preserves that value even when
        // selectedOptions is temporarily empty). Keep the path as the source
        // of truth and recover its capability by matching the advertised
        // resource/prefix boundary.
        const selectedPath = selectedOption?.value || source.value || (fallbackPrefix === undefined ? undefined : `${fallbackPrefix.replace(/\/$/, "")}/`);
        const selectedCapability = availableCapabilities.find((candidate) => candidate.capabilityId === selectedOption?.dataset.capabilityId)
          ?? availableCapabilities.find((candidate) => candidate.source.kind === "kv" && (candidate.source.path === selectedPath || (Array.isArray(candidate.scope.prefixes) && candidate.scope.prefixes.some((prefix) => `${prefix.replace(/\/$/, "")}/` === selectedPath))))
          ?? fallbackCapability;
        const selectedResourceKind = selectedOption?.dataset.resourceKind === "prefix" || (selectedPath?.endsWith("/") ?? false) ? "prefix" : "exact";
        const override = saveAs.value.trim();
        let content: ComposerContent | undefined;
        if (contentKind === "library") {
          if (selectedCapability !== undefined && selectedPath !== undefined) content = { kind: "library", source: selectedCapability.source, resource: { kind: selectedResourceKind, path: selectedPath } };
        } else if (contentKind === "text") {
          const text = author.value;
          if (text.length > 0) content = { kind: "text", text, filename: (override.length > 0 ? override : nameChip.value.trim()) || modelFilename(text) };
        } else if (chosenFile !== undefined) {
          content = { kind: "file", file: override.length > 0 && override !== chosenFile.name ? new File([chosenFile], override, { type: chosenFile.type }) : chosenFile };
        }
        if (content === undefined) { setStatus(status, "Choose what to share", "Drop a file, paste text, or pick something from your library.", "error-file", true); return; }
        const file = contentFile(content);
        const filename = contentFilename(content);
        const uploadPath = content.kind !== "library" && selectedCapability?.source.kind === "kv"
          ? selectedCapability.source.path.endsWith("/") ? `${selectedCapability.source.path}${filename}` : selectedCapability.source.path
          : filename;
        const modelInput: ShareComposerModel = {
          ...defaults,
          content,
          recipient: recipientModel(kind, recipientInput.value),
          permissions: checkedValues(form, "permission") as SharePermission[],
          expiresAt: expiryIso(),
          resource: content.kind === "library" ? content.resource : { kind: "exact", path: uploadPath },
          linkFormat: format.value as ShareLinkFormat,
          encryption: encryption.checked,
          encryptionAcknowledged: warning.checked,
          ...(delivery.value.length > 0 ? { deliveryEmail: delivery.value } : {}),
        };
        const model = validateComposerModel(modelInput);
        projectCapabilities(model);
        submit.disabled = true; setStatus(status, "Creating your link", "Encrypting in your browser. No email is being sent.", "encrypting");
        created = options.createShare === undefined ? await defaultCreate(file, model, options) : await options.createShare({ file, model });
        if (options.persistShare !== undefined) {
          const save = async (): Promise<void> => options.persistShare!({ share: created!, model, file });
          try {
            await save();
          } catch {
            setStatus(status, "Link created but not saved", "The link is only in this tab. Retry to save it to your shares, or cancel to discard it.", "error-history", true);
            const retry = el(doc, "button", "button button-primary", "Retry save"); retry.type = "button";
            const cancel = el(doc, "button", "button button-secondary", "Cancel"); cancel.type = "button";
            const retryStatus = el(doc, "span", "copy-status");
            retry.addEventListener("click", () => { retry.disabled = true; void save().then(() => { retry.remove(); cancel.remove(); retryStatus.textContent = "Saved. Create the link again to continue."; }).catch(() => { retry.disabled = false; retryStatus.textContent = "Couldn't reach your shares. Try again."; }); });
            cancel.addEventListener("click", () => { retry.remove(); cancel.remove(); retryStatus.textContent = "The unsaved link was discarded."; });
            status.append(retry, cancel, retryStatus);
            return;
          }
        }
        progress.children[0]?.setAttribute("data-state", "complete"); progress.children[1]?.setAttribute("data-state", "complete"); progress.children[2]?.setAttribute("data-state", "current"); contentSection.hidden = true; fieldset.hidden = true; expiryLabel.hidden = true; accessFieldset.hidden = true; advanced.hidden = true; note.hidden = true; submit.hidden = true;
        status.dataset.state = "created"; status.replaceChildren(el(doc, "strong", "sender-status-title result-title", "Your private link is ready"), el(doc, "span", "sender-status-detail", "Saved to your shares. Copy it now, or find it again any time."));
        const actions = el(doc, "div", "result-actions");
        const copy = el(doc, "button", "button button-primary", "Copy link") as HTMLButtonElement; copy.type = "button";
        const another = el(doc, "button", "button button-secondary", "Share another") as HTMLButtonElement; another.type = "button";
        const done = el(doc, "button", "button button-secondary composer-done", "Done") as HTMLButtonElement; done.type = "button";
        const copyStatus = el(doc, "span", "copy-status"); copyStatus.setAttribute("role", "status");
        // TC-334: this used to put the complete URL in a read-only `<input>.value`
        // — the same exposure §6.3 forbids and TC-297 removed from
        // `copyWithFallback`. `armManualCopy` keeps a decoy selected instead and
        // substitutes the real value inside the sender's own copy event, so the
        // affordance survives without the URL ever entering the DOM.
        let armed: ManualCopyHandle | undefined;
        const showManualCopy = (): void => {
          if (armed !== undefined) return;
          const manual = el(doc, "div", "manual-copy-field");
          // The denial itself is already announced through `copyStatus`.
          const help = el(doc, "p", "manual-copy-help", "The link is selected below — press Ctrl+C, or ⌘C on a Mac, to copy it. For your safety it is never shown on screen.");
          const handle = armManualCopy(created?.url ?? "", () => { copy.textContent = "Copied"; copyStatus.textContent = "Link copied."; });
          armed = handle;
          const close = el(doc, "button", "button button-secondary", "Dismiss") as HTMLButtonElement; close.type = "button";
          close.addEventListener("click", () => { handle.disarm(); manual.remove(); armed = undefined; copy.focus(); });
          manual.append(help, handle.target, close); status.append(manual); handle.select();
        };
        copy.addEventListener("click", () => { void copyText(created?.url ?? "").then(() => { copy.textContent = "Copied"; copyStatus.textContent = "Link copied to clipboard."; }).catch(() => { copyStatus.textContent = "Clipboard access was denied."; showManualCopy(); }); });
        another.addEventListener("click", () => mountShareComposer(root, options));
        done.addEventListener("click", () => options.onBack());
        actions.append(copy, another, done); status.append(actions, copyStatus);
        const notifyAction = created?.notify ?? (options.notify === undefined ? undefined : async () => {
          await options.notify?.({ share: created as ComposerShareResult, recipient: model.deliveryEmail as string, matcher: model.recipient.kind });
        });
        // Sending is always offered here for an addressed share; nothing in
        // the form gates it any more (P1-5).
        if (canNotify(model) && notifyAction !== undefined) {
          const confirm = el(doc, "button", "button button-secondary confirm-notification", "Send by email…") as HTMLButtonElement; confirm.type = "button";
          const cancel = el(doc, "button", "button button-secondary cancel-notification", "Keep link-only") as HTMLButtonElement; cancel.type = "button";
          const deliveryStatus = el(doc, "span", "copy-status notification-status");
          confirm.addEventListener("click", () => { confirm.disabled = true; void notifyAction().then(() => { deliveryStatus.textContent = `Email queued for ${model.deliveryEmail as string}.`; confirm.hidden = true; cancel.hidden = true; }).catch(() => { confirm.disabled = false; deliveryStatus.textContent = "The email didn't go out. The link above still works; try again when ready."; }); });
          cancel.addEventListener("click", () => { confirm.hidden = true; cancel.hidden = true; deliveryStatus.textContent = "No email was sent."; }); status.append(el(doc, "p", "notify-help", "The link is already yours. Send it from here only if you want us to email it."), confirm, cancel, deliveryStatus);
        }
        copy.focus();
      } catch (error) {
        console.debug("tinycloud share: sender request failed", error);
        setStatus(status, "Check the sharing details", senderFailureMessage(error), "error-invalid", true);
      }
      finally { submit.disabled = false; }
    })();
  });
}

function modelFilename(value: string): string {
  const firstLine = value.split("\n", 1)[0]?.trim().slice(0, 80);
  return firstLine === undefined || firstLine.length === 0 ? "untitled.md" : `${firstLine.replace(/[^A-Za-z0-9._-]+/g, "-").replace(/^-+|-+$/g, "") || "untitled"}.md`;
}

export { emailDomainOf };
