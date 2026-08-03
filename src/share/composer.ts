import { armManualCopy, createLinkOnlyShare, copyWithFallback, type CreateLinkOnlyShareOptions, type ManualCopyHandle } from "./link-only.js";
import { createAddressedShareLink, createShareLink, sendShareEmail } from "@tinycloud/share-sdk";
import { canonicalArtifactPath, detectHtmlArtifact } from "../artifact/bundle.js";
import { canonicalDigest } from "../email-share/protocol.js";
import type { ContentSource, SenderScope } from "../email-share/protocol.js";
import { verifyNodeProof } from "../email-share/node-verifier.js";
import type { SenderPolicy } from "../email-share/sender.js";
import { createSiblingRoots, createUnifiedPolicy, contentSourceDigestHex, nativeProjectionHashHex, registerUnifiedPolicy, requestAttestedEnforcerBinding, signV3Envelope, type UnifiedOwnerRootFactory } from "./unified-delegation.js";
import type { OpenKeyShareSession, ShareTinyCloud } from "./openkey-session.js";
import { createTinyCloudUploader, MAX_SHARE_FILE_BYTES, ownerEncryptionNetwork } from "./openkey-session.js";
import { fail, SENDER_FAILURE, senderFailureMessage } from "./sender-failure.js";
import { canonicalize, computeCid, didKeyFromEd25519PublicKey, encodeInlineShareUrl, encodeShareUrl, fromBase64Url, generateKey, seal, toBase64Url, type UnifiedPolicyCapability } from "@tinycloud/share-envelope";

/** Upper bound on the owner-space listing that backs the library picker. */
export const OWNER_LIBRARY_LIMIT = 1000;

/**
 * Prefixes the application owns in the sender's space. `tinycloud.vault`
 * stores the sender history under `vault/`, and the first run with a real
 * space listing duly offered `vault/sender-history/v1/entries/...` as things
 * to share. Those are the app's own encrypted bookkeeping records, not the
 * sender's library, and sharing one would hand a recipient the sender's own
 * history. They are excluded here rather than filtered at the picker so the
 * exclusion is stated once and testable.
 */
export const OWNER_LIBRARY_RESERVED_PREFIXES = Object.freeze(["vault/"]);

/** Control characters, DEL, and backslash — none can appear in an addressable KV key. */
function unsafeLibraryKey(value: string): boolean {
  for (const character of value) {
    const code = character.codePointAt(0) ?? 0;
    if (code < 0x20 || code === 0x7f || code === 0x5c) return true;
  }
  return false;
}

/**
 * TC-344. What the sender can share out of "your library" is exactly what is
 * already in the sender's own space, so the picker is derived from that
 * space's own key listing rather than from a server-issued capability.
 *
 * Every key becomes one exact entry. Folder/prefix entries are intentionally
 * absent until v3 has one specified shared wrapped-key design for all
 * descendants.
 *
 * Keys with empty, `.` or `..` segments, or with control characters or
 * backslashes, are dropped rather than repaired: they cannot be addressed by
 * the signed resource boundary, and a silently rewritten path would be a
 * different object from the one the sender picked.
 */
export function ownerLibraryEntries(keys: readonly string[]): readonly { readonly path: string; readonly kind: "exact" }[] {
  const entries: { readonly path: string; readonly kind: "exact" }[] = [];
  const seen = new Set<string>();
  const add = (path: string): void => {
    if (seen.has(path)) return;
    seen.add(path);
    entries.push({ path, kind: "exact" });
  };
  for (const key of keys) {
    if (typeof key !== "string") continue;
    const trimmed = key.replace(/\/+$/, "");
    const segments = trimmed.split("/");
    if (trimmed.length === 0 || segments.some((segment) => segment.length === 0 || segment === "." || segment === "..")) continue;
    if (unsafeLibraryKey(trimmed)) continue;
    if (OWNER_LIBRARY_RESERVED_PREFIXES.some((prefix) => trimmed === prefix.replace(/\/$/, "") || trimmed.startsWith(prefix))) continue;
    add(trimmed);
  }
  return entries;
}

/** The Node-signed delivery receipt, as the SDK returns it. `main.ts` forwards `authorization` and `proof` verbatim. */
export type ShareDeliveryAuthorizationReceipt = Awaited<ReturnType<ShareTinyCloud["authorizeShareDelivery"]>>;

import { loadSharePublicConfig } from "../email-share/config.js";
import { createHttpTransport } from "../email-share/transport.js";
import {
  canNotify,
  clampExpiry,
  contentFiles,
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
  readonly createShare?: (input: { readonly file: File | undefined; readonly files: readonly File[]; readonly model: ShareComposerModel }) => Promise<ComposerShareResult>;
  readonly loadCapabilities?: () => Promise<readonly { readonly capabilityId: string; readonly scope: Record<string, unknown>; readonly source: ContentSource; readonly policy: SenderPolicy }[]>;
  readonly notify?: (input: { readonly share: ComposerShareResult; readonly recipient: string; readonly matcher: RecipientKind; readonly deliveryAuthorization?: ShareDeliveryAuthorizationReceipt }) => Promise<void>;
  readonly tinycloud?: ShareTinyCloud;
  readonly persistShare?: (input: { readonly share: ComposerShareResult; readonly model: ShareComposerModel; readonly file: File | undefined; readonly files: readonly File[] }) => Promise<void>;
  /** TC-405 owner-root signer supplied by the unified delegation SDK. */
  readonly createUnifiedOwnerRoot?: UnifiedOwnerRootFactory["createOwnerRoot"];
  /** TC-405 policy/envelope signer; kept separate from Node/session transport. */
  readonly signUnifiedPolicy?: (bytes: Uint8Array) => Promise<Uint8Array>;
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

/**
 * Browser folder selections retain their paths below the selected root.
 * Canonicalization happens before any policy is signed or key is written, and
 * names that could alias another key are rejected rather than silently
 * overwriting a sibling.
 */
const uploadPathByFile = new WeakMap<File, string>();

export function selectedFilePath(file: File): string {
  return uploadPathByFile.get(file) ?? canonicalArtifactPath(file.name);
}

export function canonicalUploadFiles(selected: readonly File[]): readonly File[] {
  if (selected.length === 0) throw fail("content", "upload selection is empty");
  const browserPaths = selected.map((file) => {
    const remembered = uploadPathByFile.get(file);
    if (remembered !== undefined) return remembered;
    const relative = typeof file.webkitRelativePath === "string" && file.webkitRelativePath.length > 0
      ? file.webkitRelativePath
      : file.name;
    return relative.normalize("NFC");
  });
  const roots = browserPaths.map((path) => path.split("/")[0] ?? "");
  const sharedFolderRoot = selected.every((file) => !uploadPathByFile.has(file))
    && browserPaths.length > 0
    && browserPaths.every((path) => path.includes("/"))
    && roots.every((root) => root === roots[0])
    ? `${roots[0]}/`
    : "";
  const files: File[] = [];
  const seen = new Set<string>();
  let total = 0;
  for (const [index, input] of selected.entries()) {
    const name = input.name.normalize("NFC");
    const rawPath = browserPaths[index]!;
    const path = rawPath.startsWith(sharedFolderRoot) ? rawPath.slice(sharedFolderRoot.length) : rawPath;
    let canonicalPath: string;
  try {
      canonicalPath = canonicalArtifactPath(path);
    } catch {
      throw fail("filename", "upload path is unsafe");
    }
    const segments = canonicalPath.split("/");
    if (
      name.length === 0
      || name.trim() !== name
      || name === "."
      || name === ".."
      || /[\/\\\u0000-\u001f\u007f]/.test(name)
      || /%2f|%5c|%2e/i.test(name)
      || segments.at(-1) !== name
      || segments.some((segment) => segment.trim() !== segment || new TextEncoder().encode(segment).byteLength > 240)
    ) {
      throw fail("filename", "upload filename is unsafe");
    }
    const collisionKey = canonicalPath.toLowerCase();
    if (seen.has(collisionKey)) throw fail("filename", "upload paths would overwrite one another");
    seen.add(collisionKey);
    if (input.size === 0) throw fail("emptyFile", "uploaded document is empty");
    if (input.size > MAX_SHARE_FILE_BYTES) throw fail("fileTooLarge", "uploaded document exceeds 100 MB");
    total += input.size;
    if (!Number.isSafeInteger(total) || total > MAX_SHARE_FILE_BYTES) throw fail("fileTooLarge", "aggregate upload exceeds 100 MB");
    const output = name === input.name ? input : new File([input], name, { type: input.type, lastModified: input.lastModified });
    uploadPathByFile.set(output, canonicalPath);
    files.push(output);
  }
  return files;
}

async function defaultCreate(files: readonly File[], model: ShareComposerModel, options: ShareComposerOptions): Promise<ComposerShareResult> {
  const file = files.length === 1 ? files[0] : undefined;
  if (model.recipient.kind !== "bearer") {
    if (options.session === undefined) throw fail("session", "addressed share has no session");
    if (model.content.kind !== "library" && files.length === 0) throw fail("content", "addressed share has no file");
    return createPolicyShare(files, model, options);
  }
  if (files.length !== 1) throw fail("linkOnlyFolder", "link-only sharing supports one exact file");
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

async function createPolicyShare(files: readonly File[], model: ShareComposerModel, options: ShareComposerOptions): Promise<ComposerShareResult> {
  const file = files.length === 1 ? files[0] : undefined;
  if (options.tinycloud !== undefined) return createOwnerPolicyShare(files, model, options);
  if (files.length > 1) throw fail("linkOnlyFolder", "host-capability sharing supports one exact file");
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

async function createV3OwnerPolicyShare(files: readonly File[], model: ShareComposerModel, options: ShareComposerOptions, createOwnerRoot: UnifiedOwnerRootFactory["createOwnerRoot"]): Promise<ComposerShareResult> {
  if (!model.encryption) throw fail("plaintext", "v3 owner-policy shares require encryption");
  const tinycloud = options.tinycloud;
  if (tinycloud === undefined) throw fail("session", "v3 owner share has no TinyCloud session");
  const config = await loadSharePublicConfig();
  const file = files.length === 1 ? files[0] : undefined;
  const shareId = crypto.randomUUID();
  const resourceKind = model.resource.kind;
  const filename = contentFilename(model.content);
  if (filename.length === 0 || filename.includes("/") || filename === "." || filename === "..") throw fail("filename", "owner share filename is invalid");
  const libraryContent = contentSource(model.content);
  const selectedSource = libraryContent?.kind === "kv" ? libraryContent : undefined;
  const sourcePath = selectedSource?.path.replace(/\/+$/, "");
  const resourcePath = resourceKind === "prefix"
    ? `shares/${shareId}`
    : (resourceKind === "exact" && model.resource.path.startsWith("shares/") && selectedSource === undefined ? model.resource.path : `shares/${shareId}/${filename}`);
  const spaceId = tinycloud.spaceId;
  if (spaceId === undefined || spaceId.length === 0) throw fail("storage", "v3 owner share has no storage space");
  const network = ownerEncryptionNetwork(options.openKeyAddress);
  const key = generateKey();
  const createdAt = new Date().toISOString();
  const expiresAt = model.expiresAt;
  const ownerDid = tinycloud.did;
    try {
    if (options.signUnifiedPolicy === undefined) throw fail("internal", "v3 owner share has no owner policy signer");
    if (resourceKind !== "exact") throw fail("rejected", "v3 prefix shares require a shared wrapped content key");
    let plaintext: Uint8Array;
    let plaintextType: string;
    if (selectedSource !== undefined && sourcePath !== undefined) {
      const existing = await tinycloud.kvForSpace(spaceId).get<Uint8Array>(sourcePath, { binary: true });
      if (!existing.ok) throw fail("libraryCopy", "library file read failed during encryption");
      plaintext = existing.data.data;
      plaintextType = existing.data.headers.contentType ?? "application/octet-stream";
    } else {
      if (files.length !== 1) throw fail("content", "v3 exact upload requires one file");
      plaintext = new Uint8Array(await files[0]!.arrayBuffer());
      if (plaintext.byteLength !== files[0]!.size || plaintext.byteLength > MAX_SHARE_FILE_BYTES) throw fail("fileTooLarge", "uploaded document bytes exceed 100 MB");
      plaintextType = files[0]!.type.trim() || "application/octet-stream";
    }
    const encrypted = await tinycloud.encryption.encryptToNetwork(network, plaintext, { metadata: { contentType: plaintextType, filename } });
    plaintext.fill(0);
    if (!encrypted.ok) throw fail("rejected", "network content encryption was rejected");
    const encryptedBytes = new TextEncoder().encode(canonicalize(encrypted.data));
    const storedContent = await tinycloud.kvForSpace(spaceId).put(resourcePath, encryptedBytes, { contentType: "application/vnd.tinycloud.encrypted+json" });
    if (!storedContent.ok) throw fail("upload", "encrypted owner file upload was rejected");
    const unifiedSource = { shareId, kvResource: `tinycloud://${spaceId}/kv/${resourcePath}`, selector: resourceKind, encryptionNetwork: network, encryptedSymmetricKeyDigestHex: encrypted.data.encryptedSymmetricKeyHash, keyVersion: encrypted.data.keyVersion, mode: "mutable" as const };
    const actionNames = [...new Set(model.permissions.flatMap((action) => action === "read" ? ["tinycloud.kv/get", "tinycloud.kv/metadata"] : action === "list" ? ["tinycloud.kv/list"] : ["tinycloud.kv/put"]))].sort() as Array<"tinycloud.kv/get" | "tinycloud.kv/list" | "tinycloud.kv/metadata" | "tinycloud.kv/put">;
    const capabilities: UnifiedPolicyCapability[] = [
      { kind: "kv" as const, resource: unifiedSource.kvResource, selector: resourceKind, actions: actionNames },
      { kind: "encryption" as const, resource: network, action: "tinycloud.encryption/decrypt" as const },
    ];
    const policy = await createUnifiedPolicy({ policyId: "", ownerDid, createdAt, expiresAt, contentSource: unifiedSource, capabilityCeiling: capabilities, sign: options.signUnifiedPolicy });
    const sourceDigest = contentSourceDigestHex(unifiedSource);
    const projectionHash = nativeProjectionHashHex(capabilities);
    const attestedEnforcerBinding = await requestAttestedEnforcerBinding({ nodeOrigin: config.nodeOrigin, rootExpiresAt: expiresAt });
    const enforcerDid = String(attestedEnforcerBinding.enforcerDid);
    const roots = await createSiblingRoots({ factory: { createOwnerRoot }, ownerDid, policy: policy.policy, policyCid: policy.policyCid, policyDigestHex: policy.policyDigestHex, contentSourceDigestHex: sourceDigest, nativeProjectionHashHex: projectionHash, enforcerDid, nodeAudience: enforcerDid, expiresAt: new Date(expiresAt) });
    const registration = await registerUnifiedPolicy({ nodeOrigin: config.nodeOrigin, policy: policy.policy, policyCid: policy.policyCid, policyRoot: roots.policyRoot, enforcementRoot: roots.enforcementRoot, contentSourceDigestHex: sourceDigest, nativeProjectionHashHex: projectionHash, attestedEnforcerBinding });
    const unsigned = {
      version: 3 as const,
      shareId,
      recipientMatcher: model.recipient.kind === "exactEmail" ? { kind: "exactEmail" as const, value: model.recipient.value! } : { kind: "emailDomain" as const, value: model.recipient.value! },
      ...(model.deliveryEmail === undefined ? {} : { deliveryEmail: model.deliveryEmail }),
      actions: (["read", "list", "edit"] as const).filter((action) => model.permissions.includes(action)),
      resource: { kind: resourceKind, path: resourcePath },
      target: { origin: config.nodeOrigin, nodeAudience: enforcerDid, spaceId },
      policy: policy.policy,
      policyCid: policy.policyCid,
      policyRoot: roots.policyRoot,
      enforcementRoot: roots.enforcementRoot,
      attestedEnforcerBinding,
      contentSource: unifiedSource,
      contentSourceDigestHex: sourceDigest,
      encryptionNetwork: network,
      expiry: expiresAt,
      display: { filename },
      encrypted: true as const,
      metadata: { mediaType: contentMediaType(model.content), byteLength: file?.size ?? plaintext.byteLength, filename },
    };
    const envelope = await signV3Envelope({ unsigned, signerDid: ownerDid, sign: options.signUnifiedPolicy });
    const envelopeBytes = new TextEncoder().encode(canonicalize(envelope));
    const stored = await seal(envelopeBytes, key);
    const uploadEnvelope = async (cid: string, blob: Uint8Array, deleteAfter: string): Promise<void> => {
      const uploaded = await fetch(`${options.registryOrigin ?? options.origin}/api/share/link-only/registry/blobs`, { method: "POST", credentials: "include", cache: "no-store", redirect: "error", headers: { "content-type": "application/vnd.ipld.raw", "if-none-match": "*", "x-delete-after": deleteAfter }, body: blob as BodyInit });
      if (!uploaded.ok || cid.length === 0) throw fail("save", "v3 envelope upload was rejected");
    };
    if (model.linkFormat === "compact") await uploadEnvelope(stored.cid, stored.blob, expiresAt);
    const shareUrl = model.linkFormat === "inline" ? await encodeInlineShareUrl({ origin: config.shareOrigin, ciphertext: stored.blob, key32: key }) : encodeShareUrl({ origin: config.shareOrigin, ciphertextCid: stored.cid, key32: key });
    const binding = await fetch("/api/share/bindings", { method: "POST", credentials: "include", cache: "no-store", redirect: "error", headers: { "content-type": "application/json" }, body: JSON.stringify({ version: 3, shareCid: stored.cid, shareId, policyCid: policy.policyCid, policyRootCid: registration.policyRootCid, enforcementRootCid: registration.enforcementRootCid, contentSourceDigestHex: sourceDigest }) });
    if (!binding.ok) throw fail("save", "v3 share binding was rejected");
    return { url: shareUrl, cid: stored.cid, format: model.linkFormat, expiresAt, delegationCid: registration.enforcementRootCid };
  } finally {
    key.fill(0);
  }
}

async function createOwnerPolicyShare(files: readonly File[], model: ShareComposerModel, options: ShareComposerOptions): Promise<ComposerShareResult> {
  if (!model.encryption) throw fail("plaintext", "owner-policy shares require encryption");
  const tinycloud = options.tinycloud;
  if (tinycloud === undefined) throw fail("session", "owner share has no TinyCloud session");
  // An addressed owner share must never silently downgrade to the legacy
  // custom resolver.  The v3 owner-root factory and policy signer are a
  // single capability boundary; until both are supplied, fail closed.
  if (options.createUnifiedOwnerRoot === undefined || options.signUnifiedPolicy === undefined) {
    throw fail("internal", "unified v3 owner-share primitives are unavailable");
  }
  return createV3OwnerPolicyShare(files, model, options, options.createUnifiedOwnerRoot);
}

export async function uploadSelectedFiles(
  tinycloud: ShareTinyCloud,
  spaceId: string,
  resourcePath: string,
  resourceKind: "exact" | "prefix",
  selected: readonly File[],
): Promise<void> {
  const files = canonicalUploadFiles(selected);
  if (resourceKind === "exact" && files.length !== 1) throw fail("content", "exact upload requires one file");
  if (resourceKind === "prefix" && files.length < 2) throw fail("content", "prefix upload requires multiple files");
  const kv = tinycloud.kvForSpace(spaceId);
  for (const file of files) {
    const content = new Uint8Array(await file.arrayBuffer());
    if (content.byteLength !== file.size || content.byteLength > MAX_SHARE_FILE_BYTES) throw fail("fileTooLarge", "uploaded document bytes exceed 100 MB");
    const childPath = resourceKind === "prefix" ? `${resourcePath}/${selectedFilePath(file)}` : resourcePath;
    const result = await kv.put(childPath, content, { contentType: file.type.trim() || "application/octet-stream" });
    if (!result.ok) throw fail("upload", "owner file upload was rejected");
  }
}

export async function copySelectedSource(
  tinycloud: ShareTinyCloud,
  spaceId: string,
  sourcePath: string,
  resourceKind: "exact" | "prefix",
  targetPath: string,
): Promise<readonly string[]> {
  const kv = tinycloud.kvForSpace(spaceId);
  if (resourceKind === "exact") {
    const result = await kv.get<Uint8Array>(sourcePath, { binary: true });
    if (!result.ok) throw fail("libraryCopy", "library file read failed during copy");
    const stored = await kv.put(targetPath, result.data.data, { contentType: result.data.headers.contentType ?? "application/octet-stream" });
    if (!stored.ok) throw fail("libraryCopy", "library file write failed during copy");
    return [targetPath.split("/").at(-1) ?? targetPath];
  }
  const listing = await kv.list({ path: sourcePath, limit: 1000 });
  if (!listing.ok) throw fail("libraryOpen", "library folder listing failed");
  if (listing.data.truncated) throw fail("libraryCopy", "library folder exceeds the safe copy limit");
  const prefix = `${sourcePath}/`;
  const paths: string[] = [];
  const seen = new Set<string>();
  const children: Array<{ readonly source: string; readonly relative: string }> = [];
  for (const childPath of listing.data.keys) {
    if (!childPath.startsWith(prefix)) throw fail("libraryCopy", "library folder listing escaped its prefix");
    if (childPath.endsWith("/")) continue;
    const remainder = childPath.slice(prefix.length).replace(/\/+$/, "");
    if (remainder.length === 0) continue;
    let childName: string;
    try {
      childName = canonicalArtifactPath(remainder);
    } catch {
      throw fail("libraryCopy", "library folder contains an unsafe path");
    }
    const collisionKey = childName.toLowerCase();
    if (seen.has(collisionKey)) throw fail("libraryCopy", "library folder paths would overwrite one another");
    seen.add(collisionKey);
    children.push({ source: childPath, relative: childName });
  }
  for (const child of children) {
    const result = await kv.get<Uint8Array>(child.source, { binary: true });
    if (!result.ok) throw fail("libraryCopy", "library folder child read failed during copy");
    const stored = await kv.put(`${targetPath}/${child.relative}`, result.data.data, { contentType: result.data.headers.contentType ?? "application/octet-stream" });
    if (!stored.ok) throw fail("libraryCopy", "library folder child write failed during copy");
    paths.push(child.relative);
  }
  return paths;
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

interface ClipboardReader {
  readonly read?: () => Promise<readonly {
    readonly types: readonly string[];
    readonly getType: (type: string) => Promise<Blob>;
  }[]>;
  readonly readText?: () => Promise<string>;
}

function pastedImageFilename(mediaType: string): string {
  const extension = mediaType === "image/jpeg" ? "jpg" : mediaType.split("/")[1]?.replace("svg+xml", "svg") || "png";
  return `pasted-image.${extension}`;
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

  // What to share. Prefix content is deliberately absent until one shared
  // wrapped-key design can encrypt every descendant without widening access.
  // The kind of content is inferred from what the sender did (P1-1).
  const contentSection = el(doc, "section", "composer-section content-section");
  const drop = el(doc, "div", "content-dropzone");
  drop.setAttribute("role", "group");
  drop.setAttribute("aria-label", "Choose content to share");
  const dropTitle = el(doc, "strong", "dropzone-title", "Drop a file here");
  const dropHint = el(doc, "span", "dropzone-hint", "Or choose another way");
  const dropLimit = el(doc, "span", "dropzone-limit", "Up to 100 MB total");
  const fileInput = el(doc, "input", "upload-input") as HTMLInputElement;
  fileInput.type = "file"; fileInput.name = "document"; fileInput.accept = "*/*";
  const dropActions = el(doc, "div", "dropzone-actions");
  const chooseFileButton = el(doc, "button", "dropzone-action", "Choose file") as HTMLButtonElement;
  chooseFileButton.type = "button";
  const pasteButton = el(doc, "button", "dropzone-action dropzone-paste", "Paste from clipboard") as HTMLButtonElement;
  pasteButton.type = "button";
  const libraryLink = el(doc, "button", "dropzone-action dropzone-library", "Pick from your library") as HTMLButtonElement;
  libraryLink.type = "button";
  dropActions.append(chooseFileButton, pasteButton, libraryLink);
  const pasteStatus = el(doc, "span", "dropzone-paste-status");
  pasteStatus.setAttribute("aria-live", "polite");
  drop.append(dropTitle, dropHint, dropLimit, fileInput, dropActions, pasteStatus);

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

  // Who can open it. All recipient kinds are first-class choices.
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
  addRecipientOption(fieldset, "emailDomain", "Anyone with an email from this domain — they'll confirm their email to open it");
  addRecipientOption(fieldset, "bearer", "Anyone with the link — anyone you send it to can open it");
  recipientInput.type = "text"; recipientInput.name = "recipient-value"; recipientInput.placeholder = "name@example.com"; recipientInput.autocomplete = "email"; recipientInput.hidden = true; recipientInput.setAttribute("aria-label", "Recipient email address");
  fieldset.append(recipientInput);

  // When it stops working. The sender was never asked before (P1-2).
  const expiryFieldset = el(doc, "fieldset", "expiry-field");
  expiryFieldset.append(el(doc, "legend", "field-legend", "Link expires"));
  const expiryOptions = el(doc, "div", "expiry-options");
  for (const [value, copy] of EXPIRY_CHOICES) {
    const label = el(doc, "label", "expiry-option");
    const input = el(doc, "input", "") as HTMLInputElement;
    input.type = "radio"; input.name = "expiry"; input.value = value; input.checked = value === DEFAULT_EXPIRY_CHOICE;
    label.append(input, el(doc, "span", "expiry-option-copy", copy));
    expiryOptions.append(label);
  }
  expiryFieldset.append(expiryOptions);

  const accessFieldset = el(doc, "fieldset", "composer-section access-section");
  accessFieldset.append(el(doc, "legend", "field-legend", "What can they do?"));
  const accessControls: Array<{ readonly value: SharePermission; readonly label: HTMLLabelElement; readonly input: HTMLInputElement }> = [];
  for (const [value, label] of [["read", "Can view — open and download"], ["edit", "Can edit — open, download, and save changes"]] as const) {
    const labelNode = el(doc, "label", "permission-option"); const input = el(doc, "input", "") as HTMLInputElement; input.type = "checkbox"; input.name = "permission"; input.value = value; input.checked = value === "read"; labelNode.append(input, el(doc, "span", "permission-copy", label)); accessControls.push({ value, label: labelNode, input }); accessFieldset.append(labelNode);
  }
  const accessHint = el(doc, "p", "scope-note composer-access-hint", "Link-only shares are view-only. Choose a specific person to allow editing.");
  accessHint.hidden = true;
  const browseNotice = el(doc, "p", "scope-note composer-browse-notice", "Folder browsing is included automatically.");
  browseNotice.hidden = true;
  accessFieldset.append(accessHint, browseNotice);

  // Advanced. Everything that is a default, not a question.
  const advanced = el(doc, "details", "composer-advanced");
  advanced.append(el(doc, "summary", "composer-advanced-summary", "Advanced settings"));
  const formatLabel = el(doc, "label", "field-label", "Link style"); const format = el(doc, "select", "field-input") as HTMLSelectElement; format.name = "format"; for (const [value, label] of [["compact", "Short link (recommended)"], ["inline", "Self-contained link — very long, works without our servers"]] as const) { const option = el(doc, "option", "", label) as HTMLOptionElement; option.value = value; format.append(option); } formatLabel.append(format);
  const encryptionGroup = el(doc, "div", "composer-section encryption-group");
  const encryptionLabel = el(doc, "label", "toggle-option encryption-option"); const encryption = el(doc, "input", "") as HTMLInputElement; encryption.type = "checkbox"; encryption.name = "encryption"; encryption.checked = true; encryption.disabled = true; encryptionLabel.append(encryption, el(doc, "span", "encryption-title", "Encrypted"));
  encryptionGroup.append(encryptionLabel, el(doc, "p", "scope-note encryption-note", "Content and share details are encrypted before they leave this browser. Encryption is required for sharing."));
  const deliveryLabel = el(doc, "label", "field-label delivery-field", "Send the email somewhere else (optional)"); const delivery = el(doc, "input", "field-input delivery-value") as HTMLInputElement; delivery.type = "email"; delivery.name = "delivery-email"; deliveryLabel.append(delivery); deliveryLabel.hidden = true;
  const saveAsLabel = el(doc, "label", "field-label save-as-field", "Save it as"); const saveAs = el(doc, "input", "field-input") as HTMLInputElement; saveAs.type = "text"; saveAs.name = "save-as"; saveAs.autocomplete = "off"; saveAsLabel.append(saveAs);
  advanced.append(formatLabel, deliveryLabel, saveAsLabel);

  const note = el(doc, "p", "scope-note composer-note");
  const submit = el(doc, "button", "button button-primary create-link-button", "Create link"); submit.type = "submit";
  const status = el(doc, "div", "sender-status composer-status"); status.setAttribute("aria-live", "polite"); status.setAttribute("aria-atomic", "true");
  form.append(progress, contentSection, fieldset, expiryFieldset, accessFieldset, encryptionGroup, advanced, note, submit, status); shell.append(back, header, form); root.append(shell);

  let created: ComposerShareResult | undefined;
  let availableCapabilities: readonly { readonly capabilityId: string; readonly scope: Record<string, unknown>; readonly source: ContentSource; readonly policy: SenderPolicy }[] = [];
  // Set once the sender's own space has been listed; the library options that
  // listing produced carry no capability, so this is what names their space.
  let ownerLibrarySpaceId: string | undefined;
  // The tag mirrors the ComposerContent union: it records what the sender did,
  // it is never a control the sender has to operate.
  let contentKind: "empty" | "file" | "files" | "text" | "library" = "empty";
  let chosenFiles: readonly File[] = [];
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

  const expiryIso = (): string => {
    const choice = form.querySelector<HTMLInputElement>("input[name=expiry]:checked")?.value ?? DEFAULT_EXPIRY_CHOICE;
    return expiryFromChoice(choice as ExpiryChoice);
  };
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
    const prefixSelected = contentKind === "files"
      || (contentKind === "library" && (source.selectedOptions[0]?.dataset.resourceKind === "prefix" || source.value.endsWith("/")));
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
    accessHint.textContent = prefixSelected
      ? "Choose a specific person or company domain to share multiple files or a folder."
      : "Link-only shares are view-only. Choose a specific person to allow editing.";
    browseNotice.hidden = !prefixSelected;
    if (!addressed) { delivery.value = ""; deliveryTouched = false; }
    recipientInput.type = kind === "emailDomain" ? "text" : "email";
    recipientInput.placeholder = kind === "emailDomain" ? "example.com" : "name@example.com";
    recipientInput.autocomplete = kind === "emailDomain" ? "off" : "email";
    recipientInput.setAttribute("aria-label", kind === "emailDomain" ? "Email domain" : "Recipient email address");
    // The authorized mailbox is the natural delivery address.
    if (kind === "exactEmail" && !deliveryTouched) delivery.value = recipientInput.value.trim();
    refreshNote();
    if (addressed) { try { selectRecipientCapability(); } catch { /* submit reports invalid recipient input */ } }
  };
  form.querySelectorAll<HTMLInputElement>("input[name=recipient]").forEach((input) => input.addEventListener("change", refreshRecipient));
  recipientInput.addEventListener("input", refreshRecipient);
  form.querySelectorAll<HTMLInputElement>("input[name=expiry]").forEach((input) => input.addEventListener("change", refreshNote));
  delivery.addEventListener("input", () => { deliveryTouched = true; });
  refreshRecipient();

  const showDropzone = (): void => {
    contentKind = "empty"; chosenFiles = []; fileInput.value = ""; saveAsLabel.hidden = false;
    chosen.hidden = true; textPanel.hidden = true; libraryPanel.hidden = true; drop.hidden = false; drop.dataset.over = "false";
  };
  const chooseFiles = (selected: readonly File[]): void => {
    if (selected.length !== 1) {
      setStatus(status, "Choose one file", SENDER_FAILURE.folderUnsupported, "error-file", true);
      return;
    }
    let files: readonly File[];
    try {
      files = canonicalUploadFiles(selected);
    } catch (error) {
      setStatus(status, "Check the selected files", senderFailureMessage(error), "error-file", true);
      return;
    }
    contentKind = files.length === 1 ? "file" : "files"; chosenFiles = files;
    drop.hidden = true; textPanel.hidden = true; libraryPanel.hidden = true;
    chosen.hidden = false;
    chosenName.textContent = files.length === 1 ? files[0]!.name : `${files.length} files`;
    const detection = files.length > 1 ? detectHtmlArtifact(files.map(selectedFilePath)) : undefined;
    const artifactNote = detection?.kind === "html"
      ? " · Opens full-page as an HTML artifact"
      : files.length > 1
        ? " · Opens as a folder; add one index.html at the selected root for artifact mode"
        : "";
    chosenMeta.textContent = files.length === 1
      ? formatBytes(files[0]!.size)
      : `${files.map(selectedFilePath).join(", ")} · ${formatBytes(files.reduce((total, file) => total + file.size, 0))}${artifactNote}`;
    saveAsLabel.hidden = files.length > 1;
    refreshRecipient();
  };
  const chooseFile = (file: File): void => chooseFiles([file]);
  const chooseText = (text: string): void => {
    contentKind = "text"; chosenFiles = []; saveAsLabel.hidden = false;
    drop.hidden = true; chosen.hidden = true; libraryPanel.hidden = true; textPanel.hidden = false;
    author.value = text; nameChip.value = modelFilename(text);
  };
  const chooseLibrary = (): void => {
    contentKind = "library"; chosenFiles = []; saveAsLabel.hidden = true;
    drop.hidden = true; chosen.hidden = true; textPanel.hidden = true; libraryPanel.hidden = false;
    refreshRecipient();
  };
  const handlePaste = (event: ClipboardEvent): void => {
    const data = event.clipboardData;
    if (data === null || data === undefined) return;
    const pastedFiles = Array.from(data.files);
    if (pastedFiles.length > 0) { event.preventDefault(); chooseFiles(pastedFiles); return; }
    const text = data.getData("text/plain");
    if (text.length === 0) return;
    event.preventDefault();
    chooseText(text);
  };
  const showPasteFailure = (message: string): void => {
    pasteStatus.textContent = message;
    pasteStatus.setAttribute("role", "alert");
  };
  const readClipboard = async (): Promise<void> => {
    pasteStatus.removeAttribute("role");
    pasteStatus.textContent = "Reading clipboard…";
    pasteButton.disabled = true;
    try {
      const clipboard = doc.defaultView?.navigator.clipboard as ClipboardReader | undefined;
      if (clipboard === undefined || (clipboard.read === undefined && clipboard.readText === undefined)) {
        showPasteFailure("Clipboard access isn't available here. Press Command+V or Ctrl+V to paste instead.");
        return;
      }
      if (clipboard.read !== undefined) {
        const items = await clipboard.read();
        for (const item of items) {
          const imageType = item.types.find((type) => type.startsWith("image/"));
          if (imageType === undefined) continue;
          const blob = await item.getType(imageType);
          chooseFile(new File([blob], pastedImageFilename(blob.type || imageType), { type: blob.type || imageType }));
          pasteStatus.textContent = "";
          return;
        }
        for (const item of items) {
          if (!item.types.includes("text/plain")) continue;
          const text = await (await item.getType("text/plain")).text();
          if (text.length > 0) {
            chooseText(text);
            pasteStatus.textContent = "";
            return;
          }
        }
      }
      if (clipboard.readText !== undefined) {
        const text = await clipboard.readText();
        if (text.length > 0) {
          chooseText(text);
          pasteStatus.textContent = "";
          return;
        }
      }
      showPasteFailure("There's no text or image on your clipboard. Copy one, then try again.");
    } catch {
      showPasteFailure("Clipboard access was denied. Press Command+V or Ctrl+V to paste instead.");
    } finally {
      pasteButton.disabled = false;
    }
  };
  drop.addEventListener("click", (event) => {
    const target = event.target;
    if (target === fileInput || target === chooseFileButton || target === pasteButton || target === libraryLink) return;
    fileInput.click();
  });
  chooseFileButton.addEventListener("click", () => fileInput.click());
  pasteButton.addEventListener("click", () => { void readClipboard(); });
  drop.addEventListener("dragover", (event) => { event.preventDefault(); drop.dataset.over = "true"; });
  drop.addEventListener("dragleave", () => { drop.dataset.over = "false"; });
  drop.addEventListener("drop", (event) => {
    event.preventDefault(); drop.dataset.over = "false";
    const dropped = Array.from(event.dataTransfer?.files ?? []);
    if (dropped.length > 0) chooseFiles(dropped);
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
  fileInput.addEventListener("change", () => { const picked = Array.from(fileInput.files ?? []); if (picked.length > 0) chooseFiles(picked); });
  libraryLink.addEventListener("click", chooseLibrary);
  source.addEventListener("change", refreshRecipient);
  change.addEventListener("click", () => { showDropzone(); drop.focus(); });
  useFile.addEventListener("click", () => { showDropzone(); drop.focus(); });
  useUpload.addEventListener("click", () => { showDropzone(); drop.focus(); });

  const addLibraryOption = (path: string, kind: "exact" | "prefix", space: string, capabilityId?: string, matcher?: { readonly kind: RecipientKind; readonly value: string }): void => {
    if (kind === "prefix") return;
    const canonical = path.replace(/\/$/, "");
    if (canonical.length === 0 || /(^|\/)(?:\.|\.\.)($|\/)/.test(canonical) || /[\u0000-\u001f\u007f\\]/.test(canonical)) return;
    if (Array.from(source.options).some((existing) => existing.value === canonical)) return;
    const readable = canonical.split("/").filter(Boolean).at(-1) ?? canonical;
    const option = el(doc, "option", "", readable) as HTMLOptionElement;
    option.value = canonical; option.dataset.space = space; option.dataset.resourceKind = kind;
    if (capabilityId !== undefined) option.dataset.capabilityId = capabilityId;
    if (matcher !== undefined) { option.dataset.recipientMatcherKind = matcher.kind; option.dataset.recipientMatcherValue = matcher.value; }
    source.append(option);
    if (contentKind === "library") refreshRecipient();
  };

  /*
   * TC-344. Two independent sources feed this picker, and only one of them is
   * reachable in any shape this application can legally launch.
   *
   * The owner listing is the real one. Every addressed share the shipped app
   * creates goes through `createOwnerPolicyShare`, which works entirely inside
   * `tinycloud.spaceId` — the sender's own space, reached with the sender's
   * own wallet-rooted session. What a sender can pick from "your library" is
   * therefore just what is already in that space, so the picker asks the
   * space. No server-issued capability is involved.
   *
   * None is available either. `GET /api/share/capabilities` returns `[]` for
   * every authenticated session in every deployable shape: static sender
   * authority is forbidden (src/host/share-adapter.ts, production-server.ts,
   * scripts/validate-deploy-config.mjs) and the wallet-rooted
   * capability-issuance path that would replace it does not exist yet
   * (docs/share-host-deployment.md). Sourcing the picker only from that
   * endpoint left it permanently empty, which is why every library flow ended
   * at "Choose what to share".
   *
   * The capability listing below is retained for the host-capability composer
   * branch (`options.tinycloud === undefined`), which still selects a
   * capability by signed recipient matcher.
   */
  void (async (): Promise<void> => {
    const tinycloud = options.tinycloud;
    const spaceId = tinycloud?.spaceId;
    if (tinycloud === undefined || spaceId === undefined || spaceId.length === 0) return;
    const listing = await tinycloud.kvForSpace(spaceId).list({ limit: OWNER_LIBRARY_LIMIT });
    if (!listing.ok) return;
    ownerLibrarySpaceId = spaceId;
    for (const entry of ownerLibraryEntries(listing.data.keys)) addLibraryOption(entry.path, entry.kind, spaceId);
  })().catch(() => undefined);

  void (options.loadCapabilities === undefined ? fetch("/api/share/capabilities", { credentials: "include", cache: "no-store", redirect: "error" }).then(async (response) => response.ok ? ((await response.json()) as { readonly capabilities?: readonly { readonly capabilityId: string; readonly scope: Record<string, unknown>; readonly source: ContentSource; readonly policy: SenderPolicy }[] }).capabilities ?? [] : []) : options.loadCapabilities()).then((capabilities) => {
    availableCapabilities = capabilities;
    for (const candidate of capabilities) {
      if (candidate.source.kind !== "kv") continue;
      const matcher = signedMatcher(candidate);
      const add = (path: string, kind: "exact" | "prefix"): void => addLibraryOption(path, kind, candidate.source.space as string, candidate.capabilityId, matcher);
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
          // An owner-listed option has no capability behind it — the sender's
          // own space is the authority — so name that space directly. The
          // capability branch still applies to the host-capability composer.
          const librarySource = selectedCapability?.source
            ?? (ownerLibrarySpaceId === undefined || selectedPath === undefined ? undefined : { kind: "kv" as const, space: ownerLibrarySpaceId, path: selectedPath.replace(/\/+$/, ""), action: "tinycloud.kv/get" as const });
          if (librarySource !== undefined && selectedPath !== undefined) content = { kind: "library", source: librarySource, resource: { kind: selectedResourceKind, path: selectedPath } };
        } else if (contentKind === "text") {
          const text = author.value;
          if (text.length > 0) content = { kind: "text", text, filename: (override.length > 0 ? override : nameChip.value.trim()) || modelFilename(text) };
        } else if (chosenFiles.length === 1) {
          const chosenFile = chosenFiles[0]!;
          content = { kind: "file", file: override.length > 0 && override !== chosenFile.name ? canonicalUploadFiles([new File([chosenFile], override, { type: chosenFile.type, lastModified: chosenFile.lastModified })])[0]! : chosenFile };
        } else if (chosenFiles.length > 1) {
          content = { kind: "files", files: canonicalUploadFiles(chosenFiles) };
        }
        if (content === undefined) { setStatus(status, "Choose what to share", "Drop a file, paste text, or pick something from your library.", "error-file", true); return; }
        const files = contentFiles(content);
        const file = files.length === 1 ? files[0] : undefined;
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
          resource: content.kind === "library"
            ? content.resource
            : content.kind === "files"
              ? { kind: "prefix", path: "selected-files/" }
              : { kind: "exact", path: uploadPath },
          linkFormat: format.value as ShareLinkFormat,
          encryption: encryption.checked,
          encryptionAcknowledged: false,
          ...(delivery.value.length > 0 ? { deliveryEmail: delivery.value } : {}),
        };
        const model = validateComposerModel(modelInput);
        projectCapabilities(model);
        submit.disabled = true; setStatus(status, "Creating your link", "Encrypting in your browser. No email is being sent.", "encrypting");
        created = options.createShare === undefined ? await defaultCreate(files, model, options) : await options.createShare({ file, files, model });
        if (options.persistShare !== undefined) {
          const save = async (): Promise<void> => options.persistShare!({ share: created!, model, file, files });
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
        progress.children[0]?.setAttribute("data-state", "complete"); progress.children[1]?.setAttribute("data-state", "complete"); progress.children[2]?.setAttribute("data-state", "current"); contentSection.hidden = true; fieldset.hidden = true; expiryFieldset.hidden = true; accessFieldset.hidden = true; advanced.hidden = true; note.hidden = true; submit.hidden = true;
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
