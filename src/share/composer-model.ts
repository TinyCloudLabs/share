import type { ResourceSelector } from "@tinycloud/share-envelope";
import type { ContentSource } from "../email-share/protocol.js";
import { SENDER_FAILURE, type SenderFailureKind } from "./sender-failure.js";

function validationFailure(kind: SenderFailureKind): TypeError {
  return Object.assign(new TypeError(SENDER_FAILURE[kind]), { kind });
}

export type RecipientKind = "exactEmail" | "emailDomain" | "bearer";
export type SharePermission = "read" | "list" | "edit";
export type ShareLinkFormat = "compact" | "inline";
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
  | { readonly kind: "text"; readonly text: string; readonly filename: string }
  | { readonly kind: "library"; readonly source: ContentSource; readonly resource: ResourceSelector };

export interface ShareComposerModel {
  readonly content: ComposerContent;
  readonly recipient: RecipientSelection;
  readonly permissions: readonly SharePermission[];
  /** When the link stops working. Authored by the sender (P1-2), clamped to the signed capability boundary. */
  readonly expiresAt: string;
  readonly resource: ResourceSelector;
  readonly linkFormat: ShareLinkFormat;
  readonly encryption: boolean;
  readonly encryptionAcknowledged: boolean;
  readonly deliveryEmail?: string;
}

/** Everything the composer can default before the sender has supplied content. */
export type ComposerDefaults = Omit<ShareComposerModel, "content" | "resource">;

export type ExpiryChoice = "24h" | "7d" | "30d" | "90d";

export const EXPIRY_CHOICES: readonly (readonly [ExpiryChoice, string])[] = [
  ["24h", "24 hours"],
  ["7d", "7 days"],
  ["30d", "30 days"],
  ["90d", "90 days"],
];

const EXPIRY_MS: Record<ExpiryChoice, number> = {
  "24h": 24 * 60 * 60 * 1000,
  "7d": 7 * 24 * 60 * 60 * 1000,
  "30d": 30 * 24 * 60 * 60 * 1000,
  "90d": 90 * 24 * 60 * 60 * 1000,
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

export function contentFilename(content: ComposerContent): string {
  if (content.kind === "file") return content.file.name;
  if (content.kind === "text") return content.filename;
  return content.resource.path.split("/").filter(Boolean).at(-1) ?? "shared-resource";
}

export function contentMediaType(content: ComposerContent): string {
  if (content.kind === "file") return content.file.type || "application/octet-stream";
  if (content.kind === "text") return "text/markdown;charset=utf-8";
  return "application/octet-stream";
}

/** The persistence boundary keeps the stored history taxonomy stable. */
export function contentMode(content: ComposerContent): ComposerContentMode {
  return content.kind === "file" ? "upload" : content.kind === "text" ? "author" : "kv";
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
    linkFormat: "compact",
    encryption: true,
    encryptionAcknowledged: false,
  };
}

export function projectCapabilities(model: Pick<ShareComposerModel, "resource" | "permissions">): ProjectedCapability {
  const actionOrder: readonly SharePermission[] = ["read", "list", "edit"];
  const permissions = actionOrder.filter((action) => model.permissions.includes(action) || (action === "read" && model.resource.kind === "prefix" && model.permissions.includes("list")));
  if (permissions.length === 0 || permissions.some((value) => !["read", "list", "edit"].includes(value))) throw validationFailure("actions");
  const path = model.resource.path;
  const body = model.resource.kind === "prefix" && path.endsWith("/") ? path.slice(0, -1) : path.replace(/\/$/, "");
  const canonicalPath = model.resource.kind === "prefix" ? `${body}/` : body;
  if (body.length === 0 || /(^|\/)(?:\.|\.\.)($|\/)/.test(body) || /[\u0000-\u001f\u007f\\]/.test(body) || /%2f|%5c|%2e/i.test(body) || body.split("/").some((segment) => segment.length === 0)) {
    throw validationFailure("filename");
  }
  return { resource: { ...model.resource, path: canonicalPath }, actions: permissions };
}

export function validateComposerModel(model: ShareComposerModel): ShareComposerModel {
  const recipient = model.recipient.kind === "exactEmail"
    ? { kind: "exactEmail" as const, value: normalizeEmail(model.recipient.value ?? "") }
    : model.recipient.kind === "emailDomain"
      ? { kind: "emailDomain" as const, value: normalizeEmailDomain(model.recipient.value ?? "") }
      : { kind: "bearer" as const };
  const deliveryEmail = model.deliveryEmail === undefined ? undefined : normalizeEmail(model.deliveryEmail);
  if (!Number.isFinite(Date.parse(model.expiresAt))) throw validationFailure("expiry");
  if (recipient.kind === "exactEmail" && deliveryEmail !== undefined && deliveryEmail !== recipient.value) {
    throw validationFailure("deliveryRecipient");
  }
  if (recipient.kind === "emailDomain" && deliveryEmail !== undefined && emailDomainOf(deliveryEmail) !== recipient.value) {
    throw validationFailure("deliveryDomain");
  }
  if (!model.encryption && (recipient.kind === "exactEmail" || recipient.kind === "bearer")) {
    throw validationFailure("plaintext");
  }
  if (!model.encryption && recipient.kind === "emailDomain" && !model.encryptionAcknowledged) {
    throw validationFailure("acknowledgment");
  }
  const projected = projectCapabilities(model);
  return deliveryEmail === undefined ? { ...model, recipient, resource: projected.resource, permissions: projected.actions } : { ...model, recipient, resource: projected.resource, permissions: projected.actions, deliveryEmail };
}

/**
 * Sending is a separate, downstream action offered on the result screen — the
 * sender no longer pre-commits to being offered it (P1-5).
 */
export function canNotify(model: ShareComposerModel): boolean {
  return model.recipient.kind !== "bearer" && model.deliveryEmail !== undefined;
}
