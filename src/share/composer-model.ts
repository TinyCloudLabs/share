import type { ResourceSelector } from "@tinycloud/share-envelope";
import type { ContentSource } from "../email-share/protocol.js";

export type RecipientKind = "exactEmail" | "emailDomain" | "bearer";
export type SharePermission = "read" | "list" | "edit";
export type ShareLinkFormat = "compact" | "inline";
export type ComposerContentMode = "upload" | "author" | "kv";

export interface RecipientSelection {
  readonly kind: RecipientKind;
  readonly value?: string;
}

export interface ShareComposerModel {
  readonly recipient: RecipientSelection;
  readonly permissions: readonly SharePermission[];
  readonly resource: ResourceSelector;
  readonly source?: ContentSource;
  readonly contentMode?: ComposerContentMode;
  readonly filename?: string;
  readonly mediaType?: string;
  readonly linkFormat: ShareLinkFormat;
  readonly encryption: boolean;
  readonly encryptionAcknowledged: boolean;
  readonly notify: boolean;
  readonly deliveryEmail?: string;
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
    throw new TypeError("Enter a valid ASCII email domain.");
  }
  return domain;
}

export function normalizeEmail(value: string): string {
  if (value.trim() !== value || value.split("@").length !== 2) {
    throw new TypeError("Enter one exact email address.");
  }
  const match = EMAIL.exec(value);
  if (match === null || match[1] === undefined) throw new TypeError("Enter one exact email address.");
  return `${value.slice(0, value.length - match[1].length).slice(0, -1)}@${normalizeEmailDomain(match[1])}`;
}

export function emailDomainOf(value: string): string {
  const email = normalizeEmail(value);
  const domain = email.slice(email.lastIndexOf("@") + 1);
  return normalizeEmailDomain(domain);
}

export function defaultComposerModel(): ShareComposerModel {
  return {
    recipient: { kind: "bearer" },
    permissions: ["read"],
    resource: { kind: "exact", path: "shared-document.md" },
    linkFormat: "compact",
    encryption: true,
    encryptionAcknowledged: false,
    notify: false,
  };
}

export function projectCapabilities(model: Pick<ShareComposerModel, "resource" | "permissions">): ProjectedCapability {
  const actionOrder: readonly SharePermission[] = ["read", "list", "edit"];
  const permissions = actionOrder.filter((action) => model.permissions.includes(action) || (action === "read" && model.resource.kind === "prefix" && model.permissions.includes("list")));
  if (permissions.length === 0 || permissions.some((value) => !["read", "list", "edit"].includes(value))) throw new TypeError("Choose at least one supported access action.");
  const path = model.resource.path;
  const body = model.resource.kind === "prefix" && path.endsWith("/") ? path.slice(0, -1) : path.replace(/\/$/, "");
  const canonicalPath = model.resource.kind === "prefix" ? `${body}/` : body;
  if (body.length === 0 || /(^|\/)(?:\.|\.\.)($|\/)/.test(body) || /[\u0000-\u001f\u007f\\]/.test(body) || /%2f|%5c|%2e/i.test(body) || body.split("/").some((segment) => segment.length === 0)) {
    throw new TypeError("The share resource is not canonical.");
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
  if (model.notify && recipient.kind === "bearer") throw new TypeError("Bearer shares are link-only.");
  if (recipient.kind === "exactEmail" && deliveryEmail !== undefined && deliveryEmail !== recipient.value) {
    throw new TypeError("Exact-email delivery must match the recipient.");
  }
  if (recipient.kind === "emailDomain" && deliveryEmail !== undefined && emailDomainOf(deliveryEmail) !== recipient.value) {
    throw new TypeError("The delivery address must belong to the shared domain.");
  }
  if (!model.encryption && (recipient.kind === "exactEmail" || recipient.kind === "bearer")) {
    throw new TypeError("Exact-email and bearer shares must stay encrypted.");
  }
  if (!model.encryption && recipient.kind === "emailDomain" && !model.encryptionAcknowledged) {
    throw new TypeError("Acknowledge the policy-only encryption warning first.");
  }
  const projected = projectCapabilities(model);
  return deliveryEmail === undefined ? { ...model, recipient, resource: projected.resource, permissions: projected.actions } : { ...model, recipient, resource: projected.resource, permissions: projected.actions, deliveryEmail };
}

export function canNotify(model: ShareComposerModel): boolean {
  return model.recipient.kind !== "bearer" && model.notify && model.deliveryEmail !== undefined;
}
