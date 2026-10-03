import type { ResourceSelector } from "@tinycloud/share-envelope";
import { canonicalEmailDomain, canonicalMailbox, mailboxBelongsToDomain } from "@tinycloud/sdk-core";
import { SENDER_FAILURE, type SenderFailureKind } from "./sender-failure.js";
import { canonicalShareFilename, hasUnsafeFilenameCodePoint } from "../filename-policy.js";

export type ContentSource =
  | { readonly kind: "kv"; readonly space: string; readonly path: string; readonly action: "tinycloud.kv/get" }
  | { readonly kind: "sql"; readonly space: string; readonly database: string; readonly path: string; readonly statement: string; readonly arguments: Readonly<Record<string, number>>; readonly argumentsDigest: string; readonly action: "tinycloud.sql/read" };

function validationFailure(kind: SenderFailureKind): TypeError {
  return Object.assign(new TypeError(SENDER_FAILURE[kind]), { kind });
}

export type RecipientKind = "exactEmail" | "emailDomain" | "recipientDid" | "bearer";
export type SharePermission = "read" | "list" | "edit";
/** Persisted history taxonomy. The composer never asks for it: it is derived from the content the sender supplied. */
export type ComposerContentMode = "upload" | "author" | "kv";

export interface RecipientSelection {
  readonly kind: RecipientKind;
  readonly value?: string;
}

/**
 * What the sender is sharing, as one discriminated union so an invalid
 * combination (a file *and* a library path, text with no filename, a library
 * selection with no capability) cannot be represented. The kind is always
 * inferred from what the sender did — dropped, pasted, or picked — never
 * chosen from a control.
 */
export type ComposerContent =
  | { readonly kind: "file"; readonly file: File }
  | { readonly kind: "files"; readonly files: readonly File[] }
  | { readonly kind: "text"; readonly text: string; readonly filename: string }
  | { readonly kind: "library"; readonly source: ContentSource; readonly resource: ResourceSelector };

export interface ShareComposerModel {
  readonly content: ComposerContent;
  readonly recipient: RecipientSelection;
  readonly permissions: readonly SharePermission[];
  /** When the link stops working. Authored by the sender (P1-2), clamped to the signed capability boundary. */
  readonly expiresAt: string;
  readonly resource: ResourceSelector;
  readonly encryption: boolean;
  readonly encryptionAcknowledged: boolean;
  /** Exact-email shares: the one mailbox to email the link to. */
  readonly deliveryEmail?: string;
  /** Email-domain shares: mailboxes at exactly that domain to email the link to. */
  readonly deliveryEmails?: readonly string[];
}

/** Everything the composer can default before the sender has supplied content. */
export type ComposerDefaults = Omit<ShareComposerModel, "content" | "resource">;

export type ExpiryChoice = "24h" | "7d" | "30d";

export const EXPIRY_CHOICES: readonly (readonly [ExpiryChoice, string])[] = [
  ["24h", "24 hours"],
  ["7d", "7 days"],
  ["30d", "30 days"],
];

const EXPIRY_MS: Record<ExpiryChoice, number> = {
  "24h": 24 * 60 * 60 * 1000,
  "7d": 7 * 24 * 60 * 60 * 1000,
  "30d": 30 * 24 * 60 * 60 * 1000,
};

export const DEFAULT_EXPIRY_CHOICE: ExpiryChoice = "7d";

export function expiryFromChoice(choice: ExpiryChoice, now: number = Date.now()): string {
  return new Date(now + EXPIRY_MS[choice]).toISOString();
}

/**
 * The sender may only shorten what the signed capability already allows. A
 * boundary that is earlier than the chosen expiry always wins.
 */
export function clampExpiry(chosen: string, boundary?: string): string {
  if (boundary === undefined) return chosen;
  const limit = Date.parse(boundary);
  if (!Number.isFinite(limit)) return chosen;
  return limit < Date.parse(chosen) ? boundary : chosen;
}

export function contentFile(content: ComposerContent): File | undefined {
  if (content.kind === "file") return content.file;
  if (content.kind === "text") return new File([content.text], content.filename, { type: "text/markdown;charset=utf-8" });
  return undefined;
}

export function contentFiles(content: ComposerContent): readonly File[] {
  const file = contentFile(content);
  if (file !== undefined) return [file];
  return content.kind === "files" ? content.files : [];
}

export function contentFilename(content: ComposerContent): string {
  if (content.kind === "file") return content.file.name;
  if (content.kind === "files") return `${content.files.length} files`;
  if (content.kind === "text") return content.filename;
  return content.resource.path.split("/").filter(Boolean).at(-1) ?? "shared-resource";
}

export function contentMediaType(content: ComposerContent): string {
  if (content.kind === "file") return content.file.type || "application/octet-stream";
  if (content.kind === "files") return "application/x-tinycloud-folder";
  if (content.kind === "text") return "text/markdown;charset=utf-8";
  return "application/octet-stream";
}

/** The persistence boundary keeps the stored history taxonomy stable. */
export function contentMode(content: ComposerContent): ComposerContentMode {
  return content.kind === "file" || content.kind === "files" ? "upload" : content.kind === "text" ? "author" : "kv";
}

/** The library source, when the sender picked something already stored. */
export function contentSource(content: ComposerContent): ContentSource | undefined {
  return content.kind === "library" ? content.source : undefined;
}

export interface ProjectedCapability {
  readonly resource: ResourceSelector;
  readonly actions: readonly SharePermission[];
}

const ASCII_DOMAIN = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*$/;
const EMAIL = /^[^@\s]+@([^@\s]+)$/;

/** Normalize only the DNS side of an email. The local part remains case-sensitive. */
export function normalizeEmailDomain(value: string): string {
  const domain = value.trim().toLowerCase();
  if (!ASCII_DOMAIN.test(domain) || domain.includes("..")) {
    throw validationFailure("recipientDomain");
  }
  return domain;
}

export function normalizeEmail(value: string): string {
  if (value.trim() !== value || value.split("@").length !== 2) {
    throw validationFailure("recipientEmail");
  }
  const match = EMAIL.exec(value);
  if (match === null || match[1] === undefined) throw validationFailure("recipientEmail");
  return `${value.slice(0, value.length - match[1].length).slice(0, -1)}@${normalizeEmailDomain(match[1])}`;
}

export function normalizeRecipientDid(value: string): string {
  const did = value.trim();
  if (!/^did:[a-z0-9]+:.+$/.test(did) || did !== value || did.length > 512) {
    throw validationFailure("recipientEmail");
  }
  return did;
}

export function emailDomainOf(value: string): string {
  const email = normalizeEmail(value);
  const domain = email.slice(email.lastIndexOf("@") + 1);
  return normalizeEmailDomain(domain);
}

/**
 * Defaults only. There is deliberately no default `content` or `resource`:
 * a share with no content is not a valid model, so it is not representable.
 */
export function defaultComposerModel(now: number = Date.now()): ComposerDefaults {
  return {
    recipient: { kind: "bearer" },
    permissions: ["read"],
    expiresAt: expiryFromChoice(DEFAULT_EXPIRY_CHOICE, now),
    encryption: false,
    encryptionAcknowledged: false,
  };
}

export function projectCapabilities(model: Pick<ShareComposerModel, "resource" | "permissions">): ProjectedCapability {
  const actionOrder: readonly SharePermission[] = ["read", "list", "edit"];
  if (model.resource.kind === "exact" && model.permissions.includes("list")) throw validationFailure("actions");
  const permissions = actionOrder.filter((action) =>
    model.permissions.includes(action)
    || (model.resource.kind === "prefix" && (action === "read" || action === "list"))
  );
  if (permissions.length === 0) throw validationFailure("actions");
  const path = model.resource.path;
  const body = model.resource.kind === "prefix" && path.endsWith("/") ? path.slice(0, -1) : path.replace(/\/$/, "");
  const canonicalPath = model.resource.kind === "prefix" ? `${body}/` : body;
  if (body.length === 0 || /(^|\/)(?:\.|\.\.)($|\/)/.test(body) || body.includes("\\") || hasUnsafeFilenameCodePoint(body) || /%2f|%5c|%2e/i.test(body) || body.split("/").some((segment) => segment.length === 0)) {
    throw validationFailure("filename");
  }
  return { resource: { ...model.resource, path: canonicalPath }, actions: permissions };
}

/** A canonical recipient domain: lowercase ASCII DNS labels, two or more, no IP literal. */
export function normalizeRecipientDomain(value: string): string {
  try {
    return canonicalEmailDomain(value);
  } catch {
    throw validationFailure("recipientDomain");
  }
}

/**
 * Mailboxes typed or pasted into the domain delivery field: separated by
 * commas, semicolons, new lines or spaces, or written as `Name <address>`
 * (`"Last, First" <address>` too, and several to a line). Nothing that could
 * be an address is dropped: beside a `<…>` address, every other word with an
 * `@` is an address and the rest is display name; anywhere else, every word
 * is an address, so validation names the ones that aren't. De-duplicated in
 * order and kept as typed; validation canonicalizes them.
 */
export function parseDeliveryEmails(value: string): readonly string[] {
  const entries = deliverySegments(value).flatMap((segment) => {
    const named = [...segment.matchAll(/<([^<>]*)>/g)];
    if (named.length === 0) return segment.split(/\s+/).map((word) => word.replace(/^"(.*)"$/, "$1"));
    const found: string[] = [];
    let cursor = 0;
    for (const match of named) {
      found.push(...addressWords(segment.slice(cursor, match.index)), match[1]!.trim());
      cursor = match.index + match[0].length;
    }
    return [...found, ...addressWords(segment.slice(cursor))];
  });
  return [...new Set(entries.filter((entry) => entry.length > 0))];
}

/** Commas and semicolons separate entries outside quotes and `<…>`; a line break always does. */
function deliverySegments(value: string): string[] {
  const segments = [""];
  let quoted = false;
  let bracketed = false;
  for (const char of value) {
    if (char === "\n" || char === "\r" || (!quoted && !bracketed && (char === "," || char === ";"))) {
      segments.push("");
      quoted = false;
      bracketed = false;
      continue;
    }
    if (char === '"' && !bracketed) quoted = !quoted;
    else if (char === "<" && !quoted) bracketed = true;
    else if (char === ">" && !quoted) bracketed = false;
    segments[segments.length - 1] += char;
  }
  return segments;
}

/** The words with an `@` outside quoted display names. */
function addressWords(text: string): string[] {
  return text.replace(/"[^"]*"/g, " ").split(/\s+/).filter((word) => word.includes("@"));
}

/**
 * The issuer's canonical mailbox (lowercase), which is also the address the
 * owner's Node names in its delivery admission, when it is at `domain`.
 */
function domainDeliveryEmail(value: string, domain: string): string {
  const mailbox = canonicalMailbox(value);
  if (mailbox === undefined || !mailboxBelongsToDomain(mailbox.email, domain)) throw Object.assign(validationFailure("deliveryDomain"), { subject: value });
  return mailbox.email;
}

export function validateComposerModel(model: ShareComposerModel): ShareComposerModel {
  if (model.recipient.kind === "recipientDid") {
    throw validationFailure("recipientUnavailable");
  }
  const recipient = model.recipient.kind === "exactEmail"
    ? { kind: "exactEmail" as const, value: normalizeEmail(model.recipient.value ?? "") }
    : model.recipient.kind === "emailDomain"
      ? { kind: "emailDomain" as const, value: normalizeRecipientDomain(model.recipient.value ?? "") }
      : { kind: "bearer" as const };
  const inferredResourceKind = model.content.kind === "files"
    ? "prefix"
    : model.content.kind === "library"
      ? model.content.resource.kind
      : "exact";
  if (model.resource.kind !== inferredResourceKind) throw validationFailure("actions");
  if (model.content.kind === "files" && model.content.files.length < 2) throw validationFailure("content");
  if (model.content.kind !== "files") {
    try {
      canonicalShareFilename(contentFilename(model.content));
    } catch {
      throw validationFailure("filename");
    }
  }
  if (inferredResourceKind === "prefix") throw validationFailure("folderUnsupported");
  if (recipient.kind === "bearer" && model.permissions.some((permission) => permission !== "read")) {
    throw validationFailure("linkOnlyActions");
  }
  if ((recipient.kind === "exactEmail" || recipient.kind === "emailDomain") && !model.encryption) throw validationFailure("plaintext");
  const deliveryEmail = model.deliveryEmail === undefined ? undefined : normalizeEmail(model.deliveryEmail);
  if (!Number.isFinite(Date.parse(model.expiresAt))) throw validationFailure("expiry");
  if (deliveryEmail !== undefined && (recipient.kind !== "exactEmail" || deliveryEmail !== recipient.value)) {
    throw validationFailure("deliveryRecipient");
  }
  // One domain link can be emailed to any number of mailboxes at exactly that
  // domain; the owner's Node names each one in its signed admission.
  if (model.deliveryEmails !== undefined && model.deliveryEmails.length > 0 && recipient.kind !== "emailDomain") throw validationFailure("deliveryDomain");
  const deliveryEmails = recipient.kind !== "emailDomain" || model.deliveryEmails === undefined || model.deliveryEmails.length === 0
    ? undefined
    : [...new Set(model.deliveryEmails.map((email) => domainDeliveryEmail(email, recipient.value)))];
  const projected = projectCapabilities(model);
  const { deliveryEmail: _deliveryEmail, deliveryEmails: _deliveryEmails, ...rest } = model;
  return {
    ...rest,
    recipient,
    resource: projected.resource,
    permissions: projected.actions,
    ...(deliveryEmail === undefined ? {} : { deliveryEmail }),
    ...(deliveryEmails === undefined ? {} : { deliveryEmails }),
  };
}

/**
 * Sending is a separate, downstream action offered on the result screen — the
 * sender no longer pre-commits to being offered it (P1-5).
 */
export function canNotify(model: ShareComposerModel): boolean {
  return model.recipient.kind === "exactEmail"
    ? model.deliveryEmail !== undefined
    : model.recipient.kind === "emailDomain" && (model.deliveryEmails?.length ?? 0) > 0;
}

/** The mailboxes a Notify action emails. */
export function notificationRecipients(model: ShareComposerModel): readonly string[] {
  if (!canNotify(model)) return [];
  return model.recipient.kind === "exactEmail" ? [model.deliveryEmail!] : model.deliveryEmails!;
}
