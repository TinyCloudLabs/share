import { createLinkOnlyShare, copyWithFallback, type CreateLinkOnlyShareOptions } from "./link-only.js";
import { createAddressedShareLink, createShareLink, sendShareEmail } from "@tinycloud/share-sdk";
import type { ContentSource, SenderScope } from "../email-share/protocol.js";
import type { SenderPolicy } from "../email-share/sender.js";
import type { OpenKeyShareSession } from "./openkey-session.js";
import { createTinyCloudUploader } from "./openkey-session.js";
import { canonicalize, encodeInlineShareUrl, fromBase64Url, toBase64Url } from "@tinycloud/share-envelope";
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
  /** Explicit, post-link delivery action. The link is already stable before this is called. */
  readonly notify?: () => Promise<void>;
}

export interface ShareComposerOptions extends Omit<CreateLinkOnlyShareOptions, "createShare"> {
  readonly openKeyAddress: string;
  readonly session?: OpenKeyShareSession;
  readonly copyText?: (value: string) => Promise<void>;
  readonly createShare?: (input: { readonly file: File; readonly model: ShareComposerModel }) => Promise<ComposerShareResult>;
  readonly loadCapabilities?: () => Promise<readonly { readonly capabilityId: string; readonly scope: Record<string, unknown>; readonly source: ContentSource; readonly policy: SenderPolicy }[]>;
  readonly notify?: (input: { readonly share: ComposerShareResult; readonly recipient: string; readonly matcher: RecipientKind }) => Promise<void>;
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

async function defaultCreate(file: File, model: ShareComposerModel, options: ShareComposerOptions): Promise<ComposerShareResult> {
  if (model.recipient.kind !== "bearer") {
    if (options.session === undefined) throw new Error("Addressed policy shares require the connected OpenKey session.");
    if (model.source === undefined) throw new Error("Select an authenticated KV source before creating an addressed share.");
    return createPolicyShare(file, model, options);
  }
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
      return { url, cid: result.envelopeCid, format: model.linkFormat };
    } finally {
      result.inlineEnvelopeKey.fill(0);
    }
  }
  return { url: result.url, cid: result.envelopeCid, format: model.linkFormat };
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

async function createPolicyShare(file: File, model: ShareComposerModel, options: ShareComposerOptions): Promise<ComposerShareResult> {
  const response = options.loadCapabilities === undefined ? await fetch("/api/share/capabilities", { credentials: "include", cache: "no-store", redirect: "error" }) : undefined;
  if (response !== undefined && !response.ok) throw new Error("No authenticated sharing capability is available.");
  const capabilities = options.loadCapabilities === undefined ? ((await response!.json()) as { readonly capabilities?: readonly { readonly capabilityId: string; readonly scope: Record<string, unknown>; readonly source: ContentSource; readonly policy: SenderPolicy }[] }).capabilities ?? [] : await options.loadCapabilities();
  const candidate = capabilities.find((item) => item.source.kind === "kv" && (model.source === undefined || item.source.space === model.source.space && item.source.path === model.source.path));
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
  const delegatedScope = await authorAddressedDelegation({ scope, source, resource: model.resource, actions: model.permissions, expiresAt: scope.expiryMax ?? scope.expiresAt ?? new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(), fetchFn: options.fetchFn ?? globalThis.fetch });
  const uploader = await createTinyCloudUploader(options.session!, config, [{ scope: delegatedScope, source, policy: candidate.policy }], () => undefined);
  // Existing KV sources are already authenticated capabilities. Selecting one
  // must address that object/prefix; it must not overwrite it with the local
  // upload. Upload/author modes use the same uploader and preserve bytes.
  if (model.encryption && model.contentMode !== "kv") await uploader(file, { scope, source, policy: candidate.policy }, model.resource.path);
  const expiresAt = delegatedScope.expiryMax ?? delegatedScope.expiresAt ?? new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();
  const v2 = model.recipient.kind === "emailDomain" || model.permissions.length !== 1 || model.permissions[0] !== "read" || model.resource.kind === "prefix";
  const uploadEnvelope = async (cid: string, blob: Uint8Array, deleteAfter: string): Promise<void> => {
    const uploaded = await fetch(`${options.registryOrigin ?? options.origin}/api/share/link-only/registry/blobs`, { method: "POST", credentials: "include", cache: "no-store", redirect: "error", headers: { "content-type": "application/octet-stream", "x-delete-after": deleteAfter }, body: blob as BodyInit });
    if (!uploaded.ok) throw new Error("TinyCloud did not store the policy envelope.");
    if (cid.length === 0) throw new Error("The policy envelope CID is invalid.");
  };
  const publishBinding = async (binding: Record<string, unknown>): Promise<void> => {
    const published = await fetch("/api/share/bindings", { method: "POST", credentials: "include", cache: "no-store", redirect: "error", headers: { "content-type": "application/json" }, body: JSON.stringify({ capabilityId: candidate.capabilityId, shareCid: binding.shareCid, binding }) });
    if (!published.ok) throw new Error("TinyCloud did not persist the policy binding.");
  };
  if (v2) {
    const selectedMatcher = model.recipient.kind === "exactEmail"
      ? { kind: "exactEmail" as const, value: model.recipient.value! }
      : { kind: "emailDomain" as const, value: model.recipient.value! };
    const authority = candidate.policy as unknown as Record<string, unknown>;
    if (authority.version !== 2 || typeof authority.policyCid !== "string" || typeof authority.policyBytes !== "string" || typeof authority.policyDigest !== "string") {
      throw new Error("The trusted Node authority did not return a canonical v2 policy for this matcher and resource.");
    }
    const policy = { policyCid: authority.policyCid, policyBytes: authority.policyBytes, policyDigest: authority.policyDigest };
    const matcher = model.encryption ? selectedMatcher : { kind: "policyDigest" as const, value: policy.policyDigest };
    const bytes = new Uint8Array(await file.arrayBuffer());
    const artifact = await createAddressedShareLink({
      matcher,
      ...(model.deliveryEmail === undefined ? {} : { deliveryEmail: model.deliveryEmail }),
      source,
      scope: delegatedScope,
      policy,
      actions: model.permissions,
      resource: model.resource,
      shareId: crypto.randomUUID(),
      expiresAt,
      filename: model.encryption ? model.filename ?? file.name : "",
      mediaType: model.encryption ? model.mediaType ?? (file.type || "application/octet-stream") : "application/octet-stream",
      byteLength: model.encryption ? bytes.byteLength : 0,
      encrypted: model.encryption,
      format: model.linkFormat,
      uploadEnvelope,
      publishBinding,
    });
    return { url: artifact.shareUrl, cid: artifact.shareCid, format: model.linkFormat, notify: async () => {
      if (options.notify !== undefined) {
        await options.notify({ share: { url: artifact.shareUrl, cid: artifact.shareCid, format: model.linkFormat }, recipient: model.deliveryEmail ?? model.recipient.value!, matcher: model.recipient.kind });
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
    notify: async () => {
      await sendShareEmail({
        share: artifact,
        scope,
        adapters: createHttpTransport({ nodeOrigin: config.nodeOrigin, credentialsOrigin: config.credentialsOrigin }),
      });
    },
  };
}

async function authorAddressedDelegation(input: { readonly scope: SenderScope; readonly source: ContentSource; readonly resource: ShareComposerModel["resource"]; readonly actions: readonly SharePermission[]; readonly expiresAt: string; readonly fetchFn: typeof fetch }): Promise<SenderScope> {
  const body = {
    type: "TinyCloudShareDelegationRequest", version: 2,
    target: { origin: input.scope.targetOrigin, nodeAudience: input.scope.nodeAudience, spaceId: input.scope.spaceId },
    resource: input.resource, actions: input.actions, contentSource: input.source,
    contentSourceDigest: await digestBytes(new TextEncoder().encode(canonicalize(input.source))),
    expiresAt: input.expiresAt,
  };
  const response = await input.fetchFn(new URL("/delegate", typeof window === "undefined" ? input.scope.targetOrigin : window.location.origin), { method: "POST", credentials: "include", redirect: "error", headers: { accept: "application/vnd.tinycloud.share+json", "content-type": "application/vnd.tinycloud.share+json" }, body: JSON.stringify(body) });
  if (!response.ok) throw new Error("The authenticated Node delegation capability rejected this share.");
  const value = await response.json() as Record<string, unknown>;
  const delegationCid = typeof value.delegationCid === "string" ? value.delegationCid : typeof value.cid === "string" ? value.cid : undefined;
  if (delegationCid === undefined || delegationCid.length === 0) throw new Error("The Node delegation response did not include a CID.");
  const delegation = typeof value.delegation === "string" ? value.delegation : input.scope.delegation;
  const authorityMaterialDigest = typeof value.authorityMaterialDigest === "string" ? value.authorityMaterialDigest : input.scope.authorityMaterialDigest;
  return { ...input.scope, delegation, delegationCid, authorityMaterialDigest };
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
  const fileHelp = el(doc, "span", "upload-help", "Markdown, text, or binary bytes · up to 64 KB for link-only sharing");
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
  const refreshRecipient = (): void => {
    const kind = selectedKind(); const addressed = kind !== "bearer";
    recipientInput.hidden = !addressed; delivery.hidden = !addressed; notify.disabled = !addressed; if (!addressed) { notify.checked = false; delivery.value = ""; }
    recipientInput.type = kind === "emailDomain" ? "text" : "email"; recipientInput.placeholder = kind === "emailDomain" ? "example.com" : "name@example.com";
    encryption.disabled = kind !== "emailDomain"; if (kind !== "emailDomain") encryption.checked = true;
    warningLabel.hidden = kind !== "emailDomain" || encryption.checked;
    if (warningLabel.hidden) warning.checked = false;
    note.textContent = kind === "bearer" ? "Encryption is required for bearer links. The complete link is the authority and is never sent automatically." : kind === "emailDomain" ? "Domain authorization comes from a verified full email claim. The delivery address is metadata, never the matcher." : "Exact-email shares stay encrypted. Creating the link never sends an invitation.";
  };
  form.querySelectorAll<HTMLInputElement>("input[name=recipient]").forEach((input) => input.addEventListener("change", refreshRecipient));
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
        option.value = canonical; option.dataset.space = candidate.source.space; option.dataset.resourceKind = kind; option.dataset.capabilityId = candidate.capabilityId; source.append(option);
      };
      add(candidate.source.path, candidate.source.path.endsWith("/") ? "prefix" : "exact");
      const prefixes = candidate.scope.prefixes;
      if (Array.isArray(prefixes)) for (const prefix of prefixes) if (typeof prefix === "string") add(prefix, "prefix");
      const resources = candidate.scope.resources;
      if (Array.isArray(resources)) for (const resource of resources) if (typeof resource === "object" && resource !== null) { const value = resource as Record<string, unknown>; if (typeof value.path === "string" && (value.kind === "exact" || value.kind === "prefix")) add(value.path, value.kind); }
    }
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
      if (file === undefined && mode.value === "kv") file = new File([], "shared-resource", { type: "application/octet-stream" });
      if (file === undefined) { setStatus(status, "Choose content", "Upload a file or write Markdown/text before creating a link.", "error-file", true); return; }
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
          ? selectedCapability.source.path.endsWith("/") ? `${selectedCapability.source.path}${file.name}` : selectedCapability.source.path
          : file.name;
        const modelInput: ShareComposerModel = { recipient: recipientModel(kind, recipientInput.value), permissions: checkedValues(form, "permission") as SharePermission[], resource: mode.value === "kv" && selectedPath !== undefined ? { kind: selectedKind, path: selectedPath } : { kind: "exact", path: uploadPath }, filename: file.name, mediaType: file.type || "application/octet-stream", linkFormat: format.value as ShareLinkFormat, encryption: encryption.checked, encryptionAcknowledged: warning.checked, notify: notify.checked, ...(selectedCapability !== undefined ? { source: selectedCapability.source } : {}), ...(mode.value === "upload" || mode.value === "author" || mode.value === "kv" ? { contentMode: mode.value } : {}), ...(delivery.value.length > 0 ? { deliveryEmail: delivery.value } : {}) };
        const model = validateComposerModel(modelInput);
        projectCapabilities(model);
        submit.disabled = true; setStatus(status, "Creating your link", "Encrypting and storing the selected bytes. No notification is being sent.", "encrypting");
        created = options.createShare === undefined ? await defaultCreate(file, model, options) : await options.createShare({ file, model });
        progress.children[0]?.setAttribute("data-state", "complete"); progress.children[1]?.setAttribute("data-state", "complete"); progress.children[2]?.setAttribute("data-state", "current"); fileLabel.hidden = true; fieldset.hidden = true; accessFieldset.hidden = true; controls.hidden = true; note.hidden = true; submit.hidden = true;
        status.dataset.state = "created"; status.replaceChildren(el(doc, "strong", "sender-status-title result-title", "Your private link is ready"), el(doc, "span", "sender-status-detail", "The link is now stable and visible below. Nothing was sent yet."));
        const linkLabel = el(doc, "label", "result-link-label", "Share link"); const link = el(doc, "textarea", "share-result-link") as HTMLTextAreaElement; link.id = "generated-share-link"; link.readOnly = true; link.rows = 3; link.value = created.url; linkLabel.htmlFor = link.id; linkLabel.append(link);
        const actions = el(doc, "div", "result-actions"); const copy = el(doc, "button", "button button-primary", "Copy link"); copy.type = "button"; const another = el(doc, "button", "button button-secondary", "Share another"); another.type = "button"; const copyStatus = el(doc, "span", "copy-status"); copyStatus.setAttribute("role", "status");
        copy.addEventListener("click", () => { void copyText(created?.url ?? "").then(() => { copy.textContent = "Copied"; copyStatus.textContent = "Link copied to clipboard."; }).catch(() => { copyStatus.textContent = "Copy failed. Select the link above and copy it manually."; link.focus(); link.select(); }); });
        another.addEventListener("click", () => mountShareComposer(root, options)); actions.append(copy, another); status.append(linkLabel, actions, copyStatus);
        const notifyAction = created?.notify ?? (options.notify === undefined ? undefined : async () => {
          await options.notify?.({ share: created as ComposerShareResult, recipient: model.deliveryEmail as string, matcher: model.recipient.kind });
        });
        if (canNotify(model) && notifyAction !== undefined) {
          const confirm = el(doc, "button", "button button-secondary confirm-notification", "Confirm email notification"); confirm.type = "button"; const cancel = el(doc, "button", "button button-secondary cancel-notification", "Keep link-only"); cancel.type = "button"; const deliveryStatus = el(doc, "span", "copy-status notification-status");
          confirm.addEventListener("click", () => { confirm.disabled = true; void notifyAction().then(() => { deliveryStatus.textContent = `Notification queued for ${model.deliveryEmail as string}.`; confirm.hidden = true; cancel.hidden = true; }).catch(() => { confirm.disabled = false; deliveryStatus.textContent = "Notification was not sent. The link above is still valid; try again when ready."; }); });
          cancel.addEventListener("click", () => { confirm.hidden = true; cancel.hidden = true; deliveryStatus.textContent = "Link-only sharing selected. No notification was sent."; }); status.append(el(doc, "p", "notify-help", "The final URL is already visible. Confirm only if you want a separate exact-address notification."), confirm, cancel, deliveryStatus);
        }
        link.focus();
      } catch (error) { setStatus(status, "Check the sharing details", error instanceof Error ? error.message : "The share could not be created.", "error-invalid", true); }
      finally { submit.disabled = false; }
    })();
  });
}

function modelFilename(value: string): string {
  const firstLine = value.split("\n", 1)[0]?.trim().slice(0, 80);
  return firstLine === undefined || firstLine.length === 0 ? "untitled.md" : `${firstLine.replace(/[^A-Za-z0-9._-]+/g, "-").replace(/^-+|-+$/g, "") || "untitled"}.md`;
}

export { emailDomainOf };
