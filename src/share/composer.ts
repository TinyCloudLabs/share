import { createLinkOnlyShare, copyWithFallback, type CreateLinkOnlyShareOptions } from "./link-only.js";
import { createAddressedShareLink, createShareLink, sendShareEmail } from "@tinycloud/share-sdk";
import { canonicalDigest } from "../email-share/protocol.js";
import type { ContentSource, SenderScope } from "../email-share/protocol.js";
import { verifyNodeProof } from "../email-share/node-verifier.js";
import type { SenderPolicy } from "../email-share/sender.js";
import type { OpenKeyShareSession, ShareTinyCloud } from "./openkey-session.js";
import { createTinyCloudUploader } from "./openkey-session.js";
import { canonicalize, computeCid, didKeyFromEd25519PublicKey, encodeInlineShareUrl, encodeShareUrl, fromBase64Url, generateKey, seal, shareEnvelopeV2Schema, toBase64Url } from "@tinycloud/share-envelope";
type OwnerSharePolicyV2 = {
  readonly type: "TinyCloudSharePolicy";
  readonly version: 2;
  readonly shareId: string;
  readonly ownerDid: string;
  readonly shareKeyDid: string;
  readonly recipientMatcher: { readonly kind: "exactEmail" | "emailDomain"; readonly value: string };
  readonly target: { readonly origin: string; readonly nodeAudience: string; readonly enforcerDid: string; readonly spaceId: string };
  readonly resource: { readonly kind: "exact" | "prefix"; readonly path: string };
  readonly actions: readonly string[];
  readonly contentSource: { readonly kind: "kv"; readonly space: string; readonly path: string; readonly action: "tinycloud.kv/get" };
  readonly contentSourceDigest: string;
  readonly ownerDelegationCid: string;
  readonly expiresAt: string;
};

type OwnerSdk = {
  readonly createDelegatedShareKey: (input: { readonly extractable: boolean }) => Promise<{ readonly did: string; readonly sign: (bytes: Uint8Array) => Promise<Uint8Array>; readonly clear: () => void }>;
  readonly canonicalOwnerSharePolicy: (policy: OwnerSharePolicyV2) => Promise<{ readonly bytes: Uint8Array; readonly cid: string; readonly digest: string }>;
  readonly createPolicyEnforcementDelegation: (input: Record<string, unknown>) => Promise<{ readonly cid: string; readonly dagCbor: string; readonly issuerDid: string; readonly audienceDid: string; readonly facts: Record<string, unknown>; readonly signature: string }>;
};

async function ownerSdk(): Promise<OwnerSdk> {
  return await import("@tinycloud/web-sdk") as unknown as OwnerSdk;
}
import { loadSharePublicConfig } from "../email-share/config.js";
import { createHttpTransport } from "../email-share/transport.js";
import {
  canNotify,
  defaultComposerModel,
  emailDomainOf,
  normalizeEmail,
  normalizeEmailDomain,
  projectCapabilities,
  validateComposerModel,
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

export interface ShareComposerOptions extends Omit<CreateLinkOnlyShareOptions, "createShare"> {
  readonly openKeyAddress: string;
  readonly session?: OpenKeyShareSession;
  readonly copyText?: (value: string) => Promise<void>;
  readonly createShare?: (input: { readonly file: File | undefined; readonly model: ShareComposerModel }) => Promise<ComposerShareResult>;
  readonly loadCapabilities?: () => Promise<readonly { readonly capabilityId: string; readonly scope: Record<string, unknown>; readonly source: ContentSource; readonly policy: SenderPolicy }[]>;
  readonly notify?: (input: { readonly share: ComposerShareResult; readonly recipient: string; readonly matcher: RecipientKind; readonly deliveryAuthorization?: Record<string, unknown> }) => Promise<void>;
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
    if (options.session === undefined) throw new Error("Addressed policy shares require the connected OpenKey session.");
    if (model.source === undefined) throw new Error("Select an authenticated KV source before creating an addressed share.");
    return createPolicyShare(file, model, options);
  }
  if (file === undefined) throw new Error("A bearer share requires real content bytes.");
  const result = await createLinkOnlyShare(file, {
    origin: options.origin,
    allowBinary: true,
    ...(options.now === undefined ? {} : { now: options.now }),
    ...(options.registryOrigin === undefined ? {} : { registryOrigin: options.registryOrigin }),
    ...(options.fetchFn === undefined ? {} : { fetchFn: options.fetchFn }),
  });
  if (model.linkFormat === "inline") {
    if (result.inlineEnvelopeBlob === undefined || result.inlineEnvelopeKey === undefined) throw new Error("The selected sharing provider cannot create an inline fallback.");
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
  if (typeof value === "string") return fromBase64Url(value);
  if (Array.isArray(value) && value.every((item) => Number.isInteger(item) && item >= 0 && item <= 255)) return Uint8Array.from(value);
  if (typeof value === "object" && value !== null) {
    const entries = Object.entries(value as Record<string, unknown>).sort(([left], [right]) => Number(left) - Number(right));
    if (entries.length > 0 && entries.every(([key, item], index) => key === String(index) && typeof item === "number")) return Uint8Array.from(entries.map(([, item]) => item as number));
  }
  throw new Error(`${label} is invalid`);
}

async function digestBytes(value: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength) as ArrayBuffer);
  return toBase64Url(new Uint8Array(digest));
}

async function createPolicyShare(file: File | undefined, model: ShareComposerModel, options: ShareComposerOptions): Promise<ComposerShareResult> {
  if (options.tinycloud !== undefined) return createOwnerPolicyShare(file, model, options);
  const response = options.loadCapabilities === undefined ? await fetch("/api/share/capabilities", { credentials: "include", cache: "no-store", redirect: "error" }) : undefined;
  if (response !== undefined && !response.ok) throw new Error("No authenticated sharing capability is available.");
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
  const candidate = capabilities.find((item) => item.source.kind === "kv" && (model.source === undefined || item.source.space === model.source.space && item.source.path === model.source.path) && matcherMatches(item));
  if (candidate === undefined) throw new Error("No authenticated KV sharing capability is available.");
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
        if (!signed.ok) throw new Error("The authenticated Node signer rejected this share.");
        const result = await signed.json() as { readonly signature?: unknown };
        return bytes(result.signature, "signature");
      },
    },
  } as SenderScope;
  const source = model.source ?? candidate.source;
  const config = await loadSharePublicConfig();
  const shareId = crypto.randomUUID();
  const selectedMatcher = model.recipient.kind === "exactEmail"
    ? { kind: "exactEmail" as const, value: model.recipient.value! }
    : { kind: "emailDomain" as const, value: model.recipient.value! };
  // Domain and folder cases are already issued as persisted, signed
  // capabilities by the authenticated Node. Reuse that policy/scope so the
  // enforcing boundary checks the stored domain or prefix claim directly;
  // exact-email shares still use the one-shot attenuation authoring path.
  const authored = model.recipient.kind === "emailDomain"
    ? { scope, policy: candidate.policy }
    : await authorAddressedDelegation({ scope, source, matcher: selectedMatcher, shareId, resource: model.resource, actions: model.permissions, expiresAt: scope.expiryMax ?? scope.expiresAt ?? new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(), fetchFn: options.fetchFn ?? globalThis.fetch });
  const delegatedScope = authored.scope;
  // Existing KV sources are already authenticated capabilities. Selecting one
  // must address that object/prefix; it must not overwrite it with the local
  // upload. Upload/author modes use the same uploader and preserve bytes.
  if (model.encryption && model.contentMode !== "kv") {
    if (file === undefined) throw new Error("Upload or author content before creating this addressed share.");
    const uploader = await createTinyCloudUploader(options.session!, config, [{ scope: delegatedScope, source, policy: authored.policy }], () => undefined, options.tinycloud);
    await uploader(file, { scope: delegatedScope, source, policy: authored.policy }, model.resource.path);
  }
  const expiresAt = delegatedScope.expiryMax ?? delegatedScope.expiresAt ?? new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();
  const v2 = true;
  const uploadEnvelope = async (cid: string, blob: Uint8Array, deleteAfter: string): Promise<void> => {
    const uploaded = await fetch(`${options.registryOrigin ?? options.origin}/api/share/link-only/registry/blobs`, { method: "POST", credentials: "include", cache: "no-store", redirect: "error", headers: { "content-type": "application/vnd.ipld.raw", "if-none-match": "*", "x-delete-after": deleteAfter }, body: blob as BodyInit });
    if (!uploaded.ok) throw new Error("TinyCloud did not store the policy envelope.");
    if (cid.length === 0) throw new Error("The policy envelope CID is invalid.");
  };
  const publishBinding = async (binding: Record<string, unknown>): Promise<void> => {
    const published = await fetch("/api/share/bindings", { method: "POST", credentials: "include", cache: "no-store", redirect: "error", headers: { "content-type": "application/json" }, body: JSON.stringify({ capabilityId: candidate.capabilityId, shareCid: binding.shareCid, binding }) });
    if (!published.ok) throw new Error("TinyCloud did not persist the policy binding.");
  };
  if (v2) {
    const authority = authored.policy;
    const policyBytes = strictBase64(authority.policyBytes, "Node policy bytes");
    const policyText = new TextDecoder("utf-8", { fatal: true }).decode(policyBytes);
    const policyValue = JSON.parse(policyText) as Record<string, unknown>;
    const policyKeys = ["type", "version", "issuerDid", "recipientMatcher", "contentSource", "contentSourceDigest", "resource", "actions", "expiresAt"];
    if (Object.keys(policyValue).some((key) => !policyKeys.includes(key)) || policyKeys.some((key) => !Object.hasOwn(policyValue, key)) || canonicalize(policyValue) !== policyText || policyValue.type !== "TinyCloudSharePolicy" || policyValue.issuerDid !== scope.senderDid) throw new Error("The trusted Node policy contains unsupported fields.");
    const policyDigest = await digestBytes(policyBytes);
    if (policyDigest !== authority.policyDigest || await computeCid(policyBytes) !== authority.policyCid) throw new Error("The Node policy bytes do not match their CID or digest.");
    const rawAuthorizedActions = (scope as unknown as Record<string, unknown>).actions;
    const authorizedActions: string[] = Array.isArray(rawAuthorizedActions) ? rawAuthorizedActions.filter((value: unknown): value is string => typeof value === "string") : [];
    const actionNames = [...new Set(model.permissions.flatMap((action) => action === "read" ? ["tinycloud.kv/get", "tinycloud.kv/metadata"] : action === "list" ? ["tinycloud.kv/list"] : ["tinycloud.kv/put"]))].sort();
    if (actionNames.some((action) => !authorizedActions.includes(action) && !authorizedActions.includes(action.replace("tinycloud.kv/", "")))) throw new Error("The requested action exceeds the authenticated Node capability.");
    const policyMatcher = policyValue.recipientMatcher;
    const expectedMatcher = selectedMatcher;
    if (policyValue.version !== 2 || canonicalize(policyMatcher) !== canonicalize(expectedMatcher) || policyValue.contentSourceDigest !== await digestBytes(new TextEncoder().encode(canonicalize(source))) || policyValue.expiresAt !== expiresAt || canonicalize(policyValue.resource) !== canonicalize({ kind: model.resource.kind, value: model.resource.path.replace(/\/$/, "") }) || canonicalize(policyValue.contentSource) !== canonicalize(source) || canonicalize(policyValue.actions) !== canonicalize(actionNames)) throw new Error("The trusted Node policy is not bound to the requested share.");
    const policy = { policyCid: authority.policyCid, policyBytes: authority.policyBytes, policyDigest: authority.policyDigest };
    const matcher = model.encryption ? selectedMatcher : { kind: "policyDigest" as const, value: policy.policyDigest };
    const deliveryEmail = model.deliveryEmail;
    if (deliveryEmail === undefined) throw new Error("Addressed sharing requires a full delivery email for notification.");
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
      filename: model.encryption ? model.filename ?? file?.name ?? "shared-resource" : "",
      mediaType: model.encryption ? model.mediaType ?? (file?.type || "application/octet-stream") : "application/octet-stream",
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
  if (tinycloud === undefined) throw new Error("An authenticated TinyCloud SDK session is required.");
  const config = await loadSharePublicConfig();
  const spaceId = tinycloud.spaceId;
  if (spaceId === undefined || spaceId.length === 0) throw new Error("The authenticated TinyCloud space is unavailable.");
  const shareId = crypto.randomUUID();
  const selectedSource = model.source?.kind === "kv" ? model.source : undefined;
  const sourcePath = selectedSource?.path.replace(/\/+$/, "");
  const filename = model.filename ?? file?.name ?? sourcePath?.split("/").at(-1) ?? "shared-resource";
  if (filename.length === 0 || filename.includes("/") || filename === "." || filename === "..") throw new Error("The share filename is not canonical.");
  if (model.resource.kind === "prefix" && selectedSource === undefined) throw new Error("A prefix share must retain or copy an existing library folder.");
  const resourcePath = model.resource.kind === "prefix"
    ? `shares/${shareId}`
    : (model.resource.kind === "exact" && model.resource.path.startsWith("shares/") && selectedSource === undefined ? model.resource.path : `shares/${shareId}/${filename}`);
  if (resourcePath.length === 0 || resourcePath.endsWith("/") && model.resource.kind === "exact") throw new Error("The share source is empty or not a file.");
  const resourceKind = selectedSource === undefined ? "exact" as const : model.resource.kind;
  const source = { kind: "kv" as const, space: spaceId, path: resourcePath, action: "tinycloud.kv/get" as const };
  const actionNames = [...new Set(model.permissions.flatMap((action) => action === "read" ? ["tinycloud.kv/get", "tinycloud.kv/metadata"] : action === "list" ? ["tinycloud.kv/list"] : ["tinycloud.kv/put"]))].sort() as OwnerSharePolicyV2["actions"];
  if (actionNames.length === 0) throw new Error("The share must grant at least one action.");
  const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();
  const matcher = model.recipient.kind === "exactEmail"
    ? { kind: "exactEmail" as const, value: model.recipient.value! }
    : { kind: "emailDomain" as const, value: model.recipient.value! };
  const sdk = await ownerSdk();
  const shareKey = await sdk.createDelegatedShareKey({ extractable: false });
  try {
    if (selectedSource !== undefined && sourcePath !== undefined) {
      await copySelectedSource(tinycloud, spaceId, sourcePath, resourceKind, resourcePath);
    }
    const ownerDelegation = await (tinycloud as unknown as { createOwnerDelegation(input: Record<string, unknown>): Promise<{ readonly delegationCid: string; readonly signedDagCbor: Uint8Array }> }).createOwnerDelegation({ delegateDid: shareKey.did, spaceId, path: resourceKind === "prefix" ? `${resourcePath}/` : resourcePath, actions: actionNames, expiresAt: new Date(expiresAt) });
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
    const registration = await (tinycloud as unknown as { registerOwnerSharePolicy(input: Record<string, unknown>): Promise<{ readonly registration: { readonly registrationCid: string } }> }).registerOwnerSharePolicy({ policy: { ...canonicalPolicy, proof: policyProof }, ownerDelegation, enforcementDelegation, contentSourceDigest: sourceDigest, nodeProof: { kid: config.nodeInvitationKid, publicKey: fromBase64Url(config.nodeInvitationPublicKey) } });
    const deliveryEmail = model.deliveryEmail;
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
    const unsigned = { version: 2 as const, shareId, recipientMatcher: matcher, ...(deliveryEmail === undefined ? {} : { deliveryEmail }), actions: model.permissions, resource: { kind: resourceKind, path: resourcePath }, target: { origin: config.nodeOrigin, nodeAudience: config.nodeAudience, spaceId }, delegationCid: ownerDelegation.delegationCid, authorityMaterialHandle: registration.registration.registrationCid, authorityMaterialDigest, contentSource: source, contentSourceDigest: sourceDigest, authorizationTarget: { kind: "policy" as const, policyCid: canonicalPolicy.cid, policyBytes: toBase64Url(canonicalPolicy.bytes) }, display: model.encryption ? { filename } : {}, expiry: expiresAt, encrypted: true, metadata: { mediaType: (model.mediaType ?? file?.type) || "application/octet-stream", byteLength: file?.size ?? 0, filename }, ownerAuthority };
    shareEnvelopeV2Schema.parse(unsigned);
    const envelopeSignature = toBase64Url(await shareKey.sign(new TextEncoder().encode(`xyz.tinycloud.share/envelope/v2\0${canonicalize(unsigned)}`)));
    const envelopeBytes = new TextEncoder().encode(canonicalize({ ...unsigned, signature: { signerDid: shareKey.did, algorithm: "Ed25519", value: envelopeSignature } }));
    const key = model.encryption ? generateKey() : undefined;
    const stored = key === undefined ? { cid: await computeCid(envelopeBytes), blob: envelopeBytes } : await seal(envelopeBytes, key);
    if (key === undefined) throw new Error("Owner policy shares must be encrypted.");
    const shareUrl = model.linkFormat === "inline"
      ? await encodeInlineShareUrl({ origin: config.shareOrigin, ciphertext: stored.blob, key32: key })
      : (await (async () => { const uploaded = await fetch(`${options.registryOrigin ?? config.registryOrigin}/api/share/link-only/registry/blobs`, { method: "POST", credentials: "omit", cache: "no-store", redirect: "error", headers: { "content-type": "application/vnd.ipld.raw", "if-none-match": "*", "x-delete-after": expiresAt }, body: stored.blob as BodyInit }); if (!uploaded.ok) throw new Error("TinyCloud did not store the policy envelope."); return encodeShareUrl({ origin: config.shareOrigin, ciphertextCid: stored.cid, key32: key }); })());
    key.fill(0);
    if (selectedSource === undefined && model.contentMode !== "kv") {
      if (file === undefined) throw new Error("Upload or author content before creating this share.");
      const content = new Uint8Array(await file.arrayBuffer());
      const result = await tinycloud.kvForSpace(spaceId).put(resourcePath, content, { contentType: (model.mediaType ?? file.type) || "application/octet-stream" });
      if (!result.ok) throw new Error(result.error.message || "TinyCloud could not store this document.");
    }
    return { url: shareUrl, cid: stored.cid, format: model.linkFormat, expiresAt, delegationCid: ownerDelegation.delegationCid, ...(deliveryEmail === undefined ? {} : { notify: async () => {
      const share = { url: shareUrl, cid: stored.cid, format: model.linkFormat, expiresAt } as ComposerShareResult;
      const authorize = (tinycloud as unknown as { authorizeShareDelivery?: (input: Record<string, string>) => Promise<Record<string, unknown>> }).authorizeShareDelivery;
      if (authorize === undefined) throw new Error("The authenticated Node delivery adapter is unavailable.");
      const deliveryAuthorization = await authorize({ envelopeCid, shareCid, shareId, registrationCid: registration.registration.registrationCid, policyCid: canonicalPolicy.cid, delegationCid: ownerDelegation.delegationCid, enforcementDelegationCid: enforcementDelegation.cid, resourcePath, recipientEmail: deliveryEmail, shareUrl: share.url, documentName: filename, expiresAt: new Date(Math.min(Date.parse(expiresAt), Date.now() + 5 * 60 * 1000)).toISOString() });
      if (options.notify === undefined) throw new Error("The share notification adapter is unavailable.");
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
    if (!result.ok) throw new Error("TinyCloud could not read the selected library file.");
    const stored = await kv.put(targetPath, result.data.data, { contentType: result.data.headers.contentType ?? "application/octet-stream" });
    if (!stored.ok) throw new Error("TinyCloud could not copy the selected library file.");
    return;
  }
  const listing = await kv.list({ path: sourcePath, limit: 1000 });
  if (!listing.ok) throw new Error("TinyCloud could not list the selected library folder.");
  const prefix = `${sourcePath}/`;
  const directChildren = listing.data.keys.filter((candidate) => {
    if (!candidate.startsWith(prefix)) return false;
    const remainder = candidate.slice(prefix.length);
    return remainder.length > 0 && !remainder.includes("/");
  });
  for (const childPath of directChildren) {
    const result = await kv.get<Uint8Array>(childPath, { binary: true });
    if (!result.ok) throw new Error("TinyCloud could not read a selected library child.");
    const childName = childPath.slice(prefix.length);
    const stored = await kv.put(`${targetPath}/${childName}`, result.data.data, { contentType: result.data.headers.contentType ?? "application/octet-stream" });
    if (!stored.ok) throw new Error("TinyCloud could not copy a selected library child.");
  }
}

async function authorAddressedDelegation(input: { readonly scope: SenderScope; readonly source: ContentSource; readonly matcher: { readonly kind: "exactEmail" | "emailDomain"; readonly value: string }; readonly shareId: string; readonly resource: ShareComposerModel["resource"]; readonly actions: readonly SharePermission[]; readonly expiresAt: string; readonly fetchFn: typeof fetch }): Promise<{ readonly scope: SenderScope; readonly policy: { readonly policyCid: string; readonly policyBytes: string; readonly policyDigest: string } }> {
  if (input.scope.delegation.length === 0 || input.scope.delegationCid.length === 0 || input.scope.authorityMaterialHandle.length === 0 || input.scope.authorityMaterialDigest.length === 0) throw new Error("The authenticated delegation scope is incomplete.");
  const actions = [...new Set(input.actions.flatMap((action) => action === "read" ? ["tinycloud.kv/get", "tinycloud.kv/metadata"] : action === "list" ? ["tinycloud.kv/list"] : ["tinycloud.kv/put"]))].sort();
  const resource = { kind: input.resource.kind, value: input.resource.path.replace(/\/$/, "") } as const;
  const requestBody = { version: 2, nonce: toBase64Url(crypto.getRandomValues(new Uint8Array(32))), jti: toBase64Url(crypto.getRandomValues(new Uint8Array(16))), senderDid: input.scope.senderDid, recipientMatcher: input.matcher, targetOrigin: input.scope.targetOrigin, nodeAudience: input.scope.nodeAudience, shareCid: input.scope.delegationCid, shareId: input.shareId, delegationCid: input.scope.delegationCid, authorityMaterialHandle: input.scope.authorityMaterialHandle, authorityMaterialDigest: input.scope.authorityMaterialDigest, contentSource: input.source, contentSourceDigest: await canonicalDigest(input.source), actions, resource, expiresAt: input.expiresAt };
  const request = { ...requestBody, requestBodyDigest: await canonicalDigest(requestBody) };
  const signature = await input.scope.signer.sign({ purpose: "delegationAuthoring", message: canonicalize(request), binding: request });
  const signerDid = didKeyFromEd25519PublicKey(input.scope.signingCapability.publicKey);
  if (signerDid !== input.scope.senderDid || input.scope.signer.publicKey.length !== 32) throw new Error("The authenticated sender proof key is invalid.");
  const proof = { alg: "EdDSA", kid: `${signerDid}#${signerDid.slice("did:key:".length)}`, signature: toBase64Url(signature) };
  const response = await input.fetchFn(new URL("/delegate", input.scope.targetOrigin), { method: "POST", credentials: "omit", redirect: "error", headers: { accept: "application/json", "content-type": "application/vnd.tinycloud.delegation+json" }, body: JSON.stringify({ request, proof }) });
  if (!response.ok) {
    let detail = "";
    try {
      const error = await response.clone().json() as { readonly error?: { readonly code?: unknown } | unknown };
      const value = error.error;
      detail = typeof value === "object" && value !== null && "code" in value && typeof value.code === "string" ? `: ${value.code}` : "";
    } catch { /* Keep the user-facing error independent of an upstream response body. */ }
    throw new Error(`The authenticated Node delegation capability rejected this share (${response.status})${detail}.`);
  }
  const value = await response.json() as Record<string, unknown>;
  const required = ["type", "version", "nonce", "jti", "policyCid", "policyBytes", "policyDigest", "delegationCid", "delegationBytes", "delegationDigest", "authorityMaterialHandle", "authorityMaterialDigest", "actions", "resource", "expiresAt", "proof"];
  if (Object.keys(value).some((key) => !required.includes(key)) || required.some((key) => !Object.hasOwn(value, key)) || value.type !== "TinyCloudShareAddressedDelegation" || value.version !== 2 || value.nonce !== request.nonce || value.jti !== request.jti || typeof value.policyCid !== "string" || typeof value.policyBytes !== "string" || typeof value.policyDigest !== "string" || typeof value.delegationCid !== "string" || typeof value.delegationBytes !== "string" || typeof value.delegationDigest !== "string" || !Array.isArray(value.actions) || typeof value.expiresAt !== "string") throw new Error("The Node delegation response is not the closed v2 contract.");
  const responseProof = value.proof as Record<string, unknown>;
  if (typeof responseProof !== "object" || responseProof === null || Array.isArray(responseProof) || Object.keys(responseProof).sort().join(",") !== "alg,kid,signature" || responseProof.alg !== "EdDSA" || typeof responseProof.kid !== "string" || typeof responseProof.signature !== "string") throw new Error("The Node delegation proof is not the closed v2 contract.");
  const signedResponse = { ...value }; delete signedResponse.proof;
  await verifyNodeProof(signedResponse, responseProof as never, input.scope.trustedNode, "xyz.tinycloud.share/delegation-authoring-response/v2\0");
  const responsePolicyBytes = strictBase64(String(value.policyBytes), "Node policy bytes");
  const responseDelegationBytes = strictBase64(String(value.delegationBytes), "Node delegation bytes");
  if (value.authorityMaterialHandle !== input.scope.authorityMaterialHandle || value.authorityMaterialDigest !== input.scope.authorityMaterialDigest || canonicalize(value.actions) !== canonicalize(actions) || canonicalize(value.resource) !== canonicalize(resource) || value.expiresAt !== input.expiresAt || await digestBytes(responsePolicyBytes) !== value.policyDigest || await computeCid(responsePolicyBytes) !== value.policyCid || await digestBytes(responseDelegationBytes) !== value.delegationDigest) throw new Error("The Node delegation response is not bound to the request.");
  return { scope: { ...input.scope, delegation: String(value.delegationBytes), delegationCid: String(value.delegationCid) }, policy: { policyCid: String(value.policyCid), policyBytes: String(value.policyBytes), policyDigest: String(value.policyDigest) } };
}

function strictBase64(value: string, label: string): Uint8Array {
  let decoded: Uint8Array;
  try { decoded = fromBase64Url(value); } catch { throw new Error(`${label} is invalid`); }
  if (decoded.length === 0 || toBase64Url(decoded) !== value) throw new Error(`${label} is invalid`);
  return decoded;
}

function recipientModel(kind: RecipientKind, value: string): ShareComposerModel["recipient"] {
  if (kind === "bearer") return { kind };
  return { kind, value: kind === "emailDomain" ? normalizeEmailDomain(value) : normalizeEmail(value) };
}

export function mountShareComposer(root: HTMLElement, options: ShareComposerOptions): void {
  const doc = root.ownerDocument;
  const copyText = options.copyText ?? copyWithFallback;
  const initial = defaultComposerModel();
  root.removeAttribute("aria-busy");
  root.replaceChildren();

  const shell = el(doc, "main", "sender-shell composer-shell");
  const header = el(doc, "header", "sender-header");
  const shortAddress = options.openKeyAddress.length > 12 ? `${options.openKeyAddress.slice(0, 6)}…${options.openKeyAddress.slice(-4)}` : options.openKeyAddress;
  header.append(el(doc, "p", "sender-kicker", `OpenKey connected · ${shortAddress}`), el(doc, "h1", "sender-title", "Share with intent."), el(doc, "p", "sender-lede", "Choose the resource, the person or domain, and the smallest access that fits. TinyCloud creates the link first; delivery is always a separate confirmation."));

  const form = el(doc, "form", "sender-form composer-form") as HTMLFormElement;
  form.noValidate = true;
  const progress = el(doc, "ol", "share-progress");
  progress.setAttribute("aria-label", "Sharing steps");
  for (const [number, label, state] of [["01", "Choose", "current"], ["02", "Set access", "upcoming"], ["03", "Copy or notify", "upcoming"]] as const) {
    const item = el(doc, "li", ""); item.dataset.state = state; item.append(el(doc, "span", "", number), doc.createTextNode(label)); progress.append(item);
  }

  const fileLabel = el(doc, "label", "upload-field");
  const fileTitle = el(doc, "strong", "upload-title", "Choose a file");
  const fileHelp = el(doc, "span", "upload-help", "Markdown, text, or binary bytes · up to 100 MB");
  const fileInput = el(doc, "input", "upload-input") as HTMLInputElement;
  fileInput.type = "file"; fileInput.name = "document"; fileInput.accept = "*/*";
  const fileMeta = el(doc, "span", "upload-meta", "No file selected");
  fileLabel.append(fileTitle, fileHelp, fileInput, fileMeta);

  const fieldset = el(doc, "fieldset", "composer-section recipient-section");
  fieldset.append(el(doc, "legend", "field-legend", "Who should receive it?"));
  const recipientOptions: readonly [RecipientKind, string, string][] = [["exactEmail", "Exact email", "Only this mailbox can claim the share"], ["emailDomain", "Email domain", "Anyone with a verified mailbox in this domain"], ["bearer", "Anyone with the link", "Possession of the complete link is the authority"]];
  const recipientInput = el(doc, "input", "field-input recipient-value") as HTMLInputElement;
  for (const [kind, label, detail] of recipientOptions) {
    const labelNode = el(doc, "label", "recipient-option");
    const radio = el(doc, "input", "") as HTMLInputElement; radio.type = "radio"; radio.name = "recipient"; radio.value = kind; radio.checked = kind === initial.recipient.kind;
    labelNode.append(radio, el(doc, "span", "recipient-option-copy", `${label} — ${detail}`)); fieldset.append(labelNode);
  }
  recipientInput.type = "text"; recipientInput.name = "recipient-value"; recipientInput.placeholder = "name@example.com or example.com"; recipientInput.autocomplete = "email"; recipientInput.hidden = true; recipientInput.setAttribute("aria-label", "Recipient email or domain");
  fieldset.append(recipientInput);

  const accessFieldset = el(doc, "fieldset", "composer-section access-section");
  accessFieldset.append(el(doc, "legend", "field-legend", "What can they do?"));
  for (const [value, label, description] of [["read", "Read", "Open and download the selected resource"], ["list", "List folder", "See direct children when sharing a folder"], ["edit", "Edit text", "Save UTF-8 text or Markdown with conflict protection"]] as const) {
    const labelNode = el(doc, "label", "permission-option"); const input = el(doc, "input", "") as HTMLInputElement; input.type = "checkbox"; input.name = "permission"; input.value = value; input.checked = value === "read"; labelNode.append(input, el(doc, "span", "permission-copy", `${label} — ${description}`)); accessFieldset.append(labelNode);
  }

  const controls = el(doc, "div", "composer-controls");
  const formatLabel = el(doc, "label", "field-label", "Link format"); const format = el(doc, "select", "field-input") as HTMLSelectElement; format.name = "format"; for (const [value, label] of [["compact", "Compact registry link (recommended)"], ["inline", "Inline fallback (explicit)"]] as const) { const option = el(doc, "option", "", label) as HTMLOptionElement; option.value = value; format.append(option); } formatLabel.append(format);
  const encryptionLabel = el(doc, "label", "toggle-option"); const encryption = el(doc, "input", "") as HTMLInputElement; encryption.type = "checkbox"; encryption.name = "encryption"; encryption.checked = true; encryptionLabel.append(encryption, el(doc, "span", "", "Encrypt before storage"));
  const warningLabel = el(doc, "label", "toggle-option encryption-warning"); const warning = el(doc, "input", "") as HTMLInputElement; warning.type = "checkbox"; warning.name = "encryption-acknowledgment"; warningLabel.append(warning, el(doc, "span", "", "I understand this domain link contains policy-safe plaintext only")); warningLabel.hidden = true;
  const notifyLabel = el(doc, "label", "toggle-option"); const notify = el(doc, "input", "") as HTMLInputElement; notify.type = "checkbox"; notify.name = "notify"; notify.disabled = true; notifyLabel.append(notify, el(doc, "span", "", "Offer email notification after link creation"));
  const delivery = el(doc, "input", "field-input delivery-value") as HTMLInputElement; delivery.type = "email"; delivery.name = "delivery-email"; delivery.placeholder = "Exact delivery address (optional)"; delivery.hidden = true;
  const modeLabel = el(doc, "label", "field-label", "Content"); const mode = el(doc, "select", "field-input") as HTMLSelectElement; mode.name = "content-mode"; for (const [value, label] of [["upload", "Upload a file"], ["author", "Write Markdown or text"], ["kv", "Use an authenticated KV source"]] as const) { const option = el(doc, "option", "", label) as HTMLOptionElement; option.value = value; mode.append(option); } modeLabel.append(mode);
  const authorLabel = el(doc, "label", "field-label author-field", "Markdown or text"); const author = el(doc, "textarea", "field-input author-input") as HTMLTextAreaElement; author.name = "author-content"; author.rows = 8; author.placeholder = "Write the content to encrypt in this browser…"; authorLabel.append(author);
  const sourceLabel = el(doc, "label", "field-label source-field", "Authenticated KV source"); const source = el(doc, "select", "field-input") as HTMLSelectElement; source.name = "kv-source"; sourceLabel.append(source);
  controls.append(modeLabel, sourceLabel, authorLabel, formatLabel, encryptionLabel, warningLabel, notifyLabel, delivery);

  const note = el(doc, "p", "scope-note composer-note", "Encryption is on by default. The complete link is the authority for bearer shares; it is never sent automatically.");
  const submit = el(doc, "button", "button button-primary create-link-button", "Create private link"); submit.type = "submit";
  const status = el(doc, "div", "sender-status composer-status"); status.setAttribute("aria-live", "polite"); status.setAttribute("aria-atomic", "true");
  form.append(progress, fileLabel, fieldset, accessFieldset, controls, note, submit, status); shell.append(header, form); root.append(shell);

  let created: ComposerShareResult | undefined;
  let availableCapabilities: readonly { readonly capabilityId: string; readonly scope: Record<string, unknown>; readonly source: ContentSource; readonly policy: SenderPolicy }[] = [];
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
  const refreshRecipient = (): void => {
    const kind = selectedKind(); const addressed = kind !== "bearer";
    recipientInput.hidden = !addressed; delivery.hidden = !addressed; notify.disabled = !addressed; if (!addressed) { notify.checked = false; delivery.value = ""; }
    recipientInput.type = kind === "emailDomain" ? "text" : "email"; recipientInput.placeholder = kind === "emailDomain" ? "example.com" : "name@example.com";
    encryption.disabled = kind !== "emailDomain"; if (kind !== "emailDomain") encryption.checked = true;
    if (kind === "emailDomain" && !encryption.checked) format.value = "inline";
    warningLabel.hidden = kind !== "emailDomain" || encryption.checked;
    if (warningLabel.hidden) warning.checked = false;
    note.textContent = kind === "bearer" ? "Encryption is required for bearer links. The complete link is the authority and is never sent automatically." : kind === "emailDomain" ? "Domain authorization comes from a verified full email claim. The delivery address is metadata, never the matcher." : "Exact-email shares stay encrypted. Creating the link never sends an invitation.";
    if (addressed) { try { selectRecipientCapability(); } catch { /* submit reports invalid recipient input */ } }
  };
  form.querySelectorAll<HTMLInputElement>("input[name=recipient]").forEach((input) => input.addEventListener("change", refreshRecipient));
  recipientInput.addEventListener("input", refreshRecipient);
  encryption.addEventListener("change", refreshRecipient);
  refreshRecipient();
  authorLabel.hidden = true; sourceLabel.hidden = true;
  mode.addEventListener("change", () => { authorLabel.hidden = mode.value !== "author"; sourceLabel.hidden = mode.value !== "kv"; fileLabel.hidden = mode.value !== "upload"; });
  void (options.loadCapabilities === undefined ? fetch("/api/share/capabilities", { credentials: "include", cache: "no-store", redirect: "error" }).then(async (response) => response.ok ? ((await response.json()) as { readonly capabilities?: readonly { readonly capabilityId: string; readonly scope: Record<string, unknown>; readonly source: ContentSource; readonly policy: SenderPolicy }[] }).capabilities ?? [] : []) : options.loadCapabilities()).then((capabilities) => {
    availableCapabilities = capabilities;
    for (const candidate of capabilities) {
      if (candidate.source.kind !== "kv") continue;
      const add = (path: string, kind: "exact" | "prefix"): void => {
        const canonical = kind === "prefix" ? (path.endsWith("/") ? path : `${path}/`) : path.replace(/\/$/, "");
        if (canonical.length === 0 || /(^|\/)(?:\.|\.\.)($|\/)/.test(canonical) || /[\u0000-\u001f\u007f\\]/.test(canonical)) return;
        const option = el(doc, "option", "", `${kind === "prefix" ? "Folder" : "File"} · ${canonical}`) as HTMLOptionElement;
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
  fileInput.addEventListener("change", () => { const file = fileInput.files?.[0]; fileLabel.dataset.selected = String(file !== undefined); fileMeta.textContent = file === undefined ? "No file selected" : `${file.name} · ${file.size < 1024 ? `${file.size} B` : `${(file.size / 1024).toFixed(1)} KB`}`; });

  form.addEventListener("submit", (event) => {
    event.preventDefault();
    void (async () => {
      let file = fileInput.files?.[0];
      if (mode.value === "author") { const filename = modelFilename(author.value) ; file = new File([author.value], filename, { type: "text/markdown;charset=utf-8" }); }
      const kind = selectedKind();
      // A KV folder/file is already persisted by the authenticated source;
      // its share envelope does not require a local upload. Keep the browser
      // form usable when no local file was selected for that mode.
      if (file === undefined && mode.value !== "kv") { setStatus(status, "Choose content", "Upload a file or write Markdown/text before creating a link.", "error-file", true); return; }
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
        const selectedKind = selectedOption?.dataset.resourceKind === "prefix" || (selectedPath?.endsWith("/") ?? false) ? "prefix" : "exact";
        const uploadPath = mode.value !== "kv" && selectedCapability?.source.kind === "kv"
          ? selectedCapability.source.path.endsWith("/") ? `${selectedCapability.source.path}${file?.name ?? "shared-resource"}` : selectedCapability.source.path
          : file?.name ?? selectedPath?.split("/").filter(Boolean).at(-1) ?? "shared-resource";
        const modelInput: ShareComposerModel = { recipient: recipientModel(kind, recipientInput.value), permissions: checkedValues(form, "permission") as SharePermission[], resource: mode.value === "kv" && selectedPath !== undefined ? { kind: selectedKind, path: selectedPath } : { kind: "exact", path: uploadPath }, filename: file?.name ?? selectedPath?.split("/").filter(Boolean).at(-1) ?? "shared-resource", mediaType: file?.type || "application/octet-stream", linkFormat: format.value as ShareLinkFormat, encryption: encryption.checked, encryptionAcknowledged: warning.checked, notify: notify.checked, ...(selectedCapability !== undefined ? { source: selectedCapability.source } : {}), ...(mode.value === "upload" || mode.value === "author" || mode.value === "kv" ? { contentMode: mode.value } : {}), ...(delivery.value.length > 0 ? { deliveryEmail: delivery.value } : {}) };
        const model = validateComposerModel(modelInput);
        projectCapabilities(model);
        submit.disabled = true; setStatus(status, "Creating your link", "Encrypting and storing the selected bytes. No notification is being sent.", "encrypting");
        created = options.createShare === undefined ? await defaultCreate(file, model, options) : await options.createShare({ file, model });
        if (options.persistShare !== undefined) {
          const save = async (): Promise<void> => options.persistShare!({ share: created!, model, file });
          try {
            await save();
          } catch {
            setStatus(status, "Link created but not saved", "The link remains only in memory. Retry to save this exact artifact, or cancel to discard it.", "error-history", true);
            const retry = el(doc, "button", "button button-primary", "Retry save"); retry.type = "button";
            const cancel = el(doc, "button", "button button-secondary", "Cancel"); cancel.type = "button";
            const retryStatus = el(doc, "span", "copy-status");
            retry.addEventListener("click", () => { retry.disabled = true; void save().then(() => { retry.remove(); cancel.remove(); retryStatus.textContent = "Saved. Create the link again to continue."; }).catch(() => { retry.disabled = false; retryStatus.textContent = "The encrypted library could not be reached. Try again."; }); });
            cancel.addEventListener("click", () => { retry.remove(); cancel.remove(); retryStatus.textContent = "The unsaved link was discarded."; });
            status.append(retry, cancel, retryStatus);
            return;
          }
        }
        progress.children[0]?.setAttribute("data-state", "complete"); progress.children[1]?.setAttribute("data-state", "complete"); progress.children[2]?.setAttribute("data-state", "current"); fileLabel.hidden = true; fieldset.hidden = true; accessFieldset.hidden = true; controls.hidden = true; note.hidden = true; submit.hidden = true;
        status.dataset.state = "created"; status.replaceChildren(el(doc, "strong", "sender-status-title result-title", "Your private link is ready"), el(doc, "span", "sender-status-detail", "The link is encrypted in your sender library. Copy it now, or return to All shares to open it later."));
        const actions = el(doc, "div", "result-actions"); const copy = el(doc, "button", "button button-primary", "Copy link"); copy.type = "button"; const another = el(doc, "button", "button button-secondary", "Share another"); another.type = "button"; const copyStatus = el(doc, "span", "copy-status"); copyStatus.setAttribute("role", "status");
        const showManualCopy = (): void => {
          const manual = el(doc, "div", "manual-copy-field");
          const label = el(doc, "label", "result-link-label", "Clipboard access was denied. Copy the link from this temporary field, then close it.");
          const field = el(doc, "input", "field-input") as HTMLInputElement; field.type = "text"; field.readOnly = true; field.autocomplete = "off"; field.value = created?.url ?? ""; label.append(field);
          const close = el(doc, "button", "button button-secondary", "Close temporary field"); close.type = "button"; close.addEventListener("click", () => { field.value = ""; manual.remove(); copy.focus(); });
          manual.append(label, close); status.append(manual); field.focus(); field.select();
        };
        copy.addEventListener("click", () => { void copyText(created?.url ?? "").then(() => { copy.textContent = "Copied"; copyStatus.textContent = "Link copied to clipboard."; }).catch(() => { copyStatus.textContent = "Clipboard access was denied."; showManualCopy(); }); });
        another.addEventListener("click", () => mountShareComposer(root, options)); actions.append(copy, another); status.append(actions, copyStatus);
        const notifyAction = created?.notify ?? (options.notify === undefined ? undefined : async () => {
          await options.notify?.({ share: created as ComposerShareResult, recipient: model.deliveryEmail as string, matcher: model.recipient.kind });
        });
        if (canNotify(model) && notifyAction !== undefined) {
          const confirm = el(doc, "button", "button button-secondary confirm-notification", "Confirm email notification"); confirm.type = "button"; const cancel = el(doc, "button", "button button-secondary cancel-notification", "Keep link-only"); cancel.type = "button"; const deliveryStatus = el(doc, "span", "copy-status notification-status");
          confirm.addEventListener("click", () => { confirm.disabled = true; void notifyAction().then(() => { deliveryStatus.textContent = `Notification queued for ${model.deliveryEmail as string}.`; confirm.hidden = true; cancel.hidden = true; }).catch(() => { confirm.disabled = false; deliveryStatus.textContent = "Notification was not sent. The link above is still valid; try again when ready."; }); });
          cancel.addEventListener("click", () => { confirm.hidden = true; cancel.hidden = true; deliveryStatus.textContent = "Link-only sharing selected. No notification was sent."; }); status.append(el(doc, "p", "notify-help", "The final URL is already visible. Confirm only if you want a separate exact-address notification."), confirm, cancel, deliveryStatus);
        }
        copy.focus();
      } catch (error) {
        const detail = error instanceof Error ? error.message : typeof error === "string" ? error : "The share could not be created.";
        setStatus(status, "Check the sharing details", detail, "error-invalid", true);
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
