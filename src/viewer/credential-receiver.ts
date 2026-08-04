import { canonicalize, type ShareEnvelopeV3 } from "@tinycloud/share-envelope";
import type { InlineEncryptedEnvelope, TinyCloudWeb } from "@tinycloud/web-sdk";
import { canonicalDigest, emailCredentialRequirement, EMAIL_CREDENTIAL_DESCRIPTOR, type EmailCredentialRequirement } from "../credentials/email.js";

export { EMAIL_CREDENTIAL_DESCRIPTOR, type EmailCredentialRequirement } from "../credentials/email.js";

/**
 * This value may only be constructed from `resolveShare`'s verified result.
 * Query parameters, popup messages, and display/prefill strings are
 * intentionally absent from the type.
 */
export interface VerifiedCredentialShare {
  readonly envelope: ShareEnvelopeV3;
  readonly policy: Record<string, unknown>;
  readonly shareCid: string;
}

export type CredentialReceiverState =
  | "checking-existing"
  | "opening-verification"
  | "proving"
  | "waiting-for-approval"
  | "verifying"
  | "saving"
  | "authorizing-access"
  | "opening-content"
  | "success";

export interface CredentialProgressLike {
  readonly state: "checking" | "collecting" | "challenging" | "proving" | "signing" | "issuing" | "verifying" | "saving" | "success" | "recovery";
}

export interface VerifiedCredentialLike {
  readonly holderDid: string;
  readonly subjectDid: string;
  readonly credentialDigest: string;
  readonly descriptorDigest: string;
  readonly issuerDid: string;
  readonly issuerKid: string;
  readonly profile: { readonly id: string; readonly version: 1 };
  readonly credentialType: { readonly id: string; readonly version: 1 };
  readonly claims: Readonly<Record<string, string>>;
  readonly credential: string;
}

export interface StoredCredentialLike {
  readonly ownerDid: string;
  readonly recordId: string;
  readonly holderDid: string;
  readonly requirementDigest: string;
  readonly descriptorDigest: string;
  readonly issuerDid: string;
  readonly issuerKid: string;
  readonly profile: { readonly id: string; readonly version: 1 };
  readonly credentialType: { readonly id: string; readonly version: 1 };
  readonly credentialDigest: string;
  readonly claims: Readonly<Record<string, string>>;
}

export interface CredentialStorageReceiptLike {
  readonly ownerDid: string;
  readonly recordId: string;
}

export interface CredentialEnsureResultLike {
  readonly status: "reused" | "acquired";
  readonly credential: VerifiedCredentialLike;
  readonly record: StoredCredentialLike;
  readonly receipt?: CredentialStorageReceiptLike;
}

export type ActiveCredentialClient = TinyCloudWeb;

export interface CredentialShareReadOperation {
  readonly type: "TinyCloudInterruptedShareRead";
  readonly version: 1;
  readonly shareCid: string;
  readonly envelope: ShareEnvelopeV3;
}

export interface CredentialAuthorizedContent {
  readonly type: "TinyCloudCredentialAuthorizedContent";
  readonly version: 1;
  readonly delegationCid: string;
  readonly bytes: Uint8Array;
  readonly mediaType: string;
}

export type CredentialReceiverErrorCode =
  | "UNSUPPORTED_REQUIREMENT"
  | "ACTIVE_SESSION_REQUIRED"
  | "CREDENTIAL_NOT_DURABLE"
  | "POLICY_ADMISSION_FAILED"
  | "INVOCATION_FAILED";

export class CredentialReceiverError extends Error {
  readonly name = "CredentialReceiverError";
  constructor(readonly code: CredentialReceiverErrorCode, message: string, options?: ErrorOptions) {
    super(message, options);
  }
}

function receiverError(code: CredentialReceiverErrorCode, message: string, cause: unknown): CredentialReceiverError {
  return cause instanceof CredentialReceiverError ? cause : new CredentialReceiverError(code, message, { cause });
}

export function credentialRequirementFromVerifiedShare(share: VerifiedCredentialShare): EmailCredentialRequirement {
  if (share.envelope.version !== 3 || share.envelope.recipientMatcher.kind !== "exactEmail") {
    throw new CredentialReceiverError("UNSUPPORTED_REQUIREMENT", "The verified share does not contain a supported credential requirement");
  }
  if (canonicalize(share.policy) !== canonicalize(share.envelope.policy)) {
    throw new CredentialReceiverError("UNSUPPORTED_REQUIREMENT", "The verified policy does not match the signed share envelope");
  }
  try {
    return emailCredentialRequirement(share.envelope.recipientMatcher.value);
  } catch (cause) {
    throw new CredentialReceiverError("UNSUPPORTED_REQUIREMENT", "The verified share does not contain a supported exact-email requirement", { cause });
  }
}

interface SignedCredentialRequirementProjection {
  readonly type: "TinyCloudPolicyCredentialRequirement";
  readonly version: 1;
  readonly requirementDigest: string;
  readonly descriptorDigest: string;
  readonly issuerDid: string;
  readonly issuerKid: string;
  readonly profile: { readonly id: string; readonly version: 1 };
  readonly credentialType: { readonly id: string; readonly version: 1 };
}

export async function validateCredentialProjectionFromVerifiedShare(
  share: VerifiedCredentialShare,
  requirement: EmailCredentialRequirement,
): Promise<SignedCredentialRequirementProjection> {
  const raw = share.policy.credentialRequirement;
  if (share.policy.schema !== "xyz.tinycloud.policy/policy/v2" || raw === null || typeof raw !== "object" || Array.isArray(raw)) {
    throw new CredentialReceiverError("UNSUPPORTED_REQUIREMENT", "The verified policy does not contain a supported credential projection");
  }
  const value = raw as Record<string, unknown>;
  const profile = value.profile;
  const credentialType = value.credentialType;
  const exactKeys = ["credentialType", "descriptorDigest", "issuerDid", "issuerKid", "profile", "requirementDigest", "type", "version"];
  if (Object.keys(value).sort().join("\0") !== exactKeys.sort().join("\0")
    || value.type !== "TinyCloudPolicyCredentialRequirement" || value.version !== 1
    || typeof value.requirementDigest !== "string" || typeof value.descriptorDigest !== "string"
    || value.issuerDid !== EMAIL_CREDENTIAL_DESCRIPTOR.issuer.did || value.issuerKid !== EMAIL_CREDENTIAL_DESCRIPTOR.issuer.kid
    || profile === null || typeof profile !== "object" || Array.isArray(profile) || Object.keys(profile).sort().join("\0") !== "id\0version" || (profile as Record<string, unknown>).id !== requirement.profile.id || (profile as Record<string, unknown>).version !== 1
    || credentialType === null || typeof credentialType !== "object" || Array.isArray(credentialType) || Object.keys(credentialType).sort().join("\0") !== "id\0version" || (credentialType as Record<string, unknown>).id !== requirement.credentialType.id || (credentialType as Record<string, unknown>).version !== 1
    || value.requirementDigest !== canonicalDigest(requirement)
    || value.descriptorDigest !== canonicalDigest(EMAIL_CREDENTIAL_DESCRIPTOR)) {
    throw new CredentialReceiverError("UNSUPPORTED_REQUIREMENT", "The verified policy credential projection does not match the requested credential");
  }
  return value as unknown as SignedCredentialRequirementProjection;
}

export function mapCredentialProgress(progress: CredentialProgressLike): CredentialReceiverState | undefined {
  switch (progress.state) {
    case "checking": return "checking-existing";
    case "collecting":
    case "challenging": return "opening-verification";
    case "proving": return "proving";
    case "signing": return "waiting-for-approval";
    case "issuing":
    case "verifying": return "verifying";
    case "saving": return "saving";
    case "success": return undefined;
    case "recovery": return "opening-verification";
  }
}

function assertDurableCredential(result: CredentialEnsureResultLike, readback: StoredCredentialLike | undefined, holderDid: string, email: string, projection: SignedCredentialRequirementProjection): void {
  const credential = result.credential;
  const record = result.record;
  if (credential.holderDid !== holderDid || credential.subjectDid !== holderDid || record.holderDid !== holderDid
    || !record.ownerDid.startsWith("did:pkh:") || record.ownerDid === holderDid
    || credential.claims.email !== email || record.claims.email !== email
    || credential.descriptorDigest !== projection.descriptorDigest || record.descriptorDigest !== projection.descriptorDigest || record.requirementDigest !== projection.requirementDigest
    || credential.issuerDid !== projection.issuerDid || record.issuerDid !== projection.issuerDid || credential.issuerKid !== projection.issuerKid || record.issuerKid !== projection.issuerKid
    || credential.profile.id !== projection.profile.id || record.profile.id !== projection.profile.id || credential.profile.version !== 1 || record.profile.version !== 1
    || credential.credentialType.id !== projection.credentialType.id || record.credentialType.id !== projection.credentialType.id || credential.credentialType.version !== 1 || record.credentialType.version !== 1
    || credential.credentialDigest.length === 0 || record.credentialDigest !== credential.credentialDigest
    || readback === undefined || readback.recordId !== record.recordId || readback.ownerDid !== record.ownerDid
    || readback.holderDid !== holderDid || readback.requirementDigest !== projection.requirementDigest || readback.descriptorDigest !== projection.descriptorDigest
    || readback.issuerDid !== projection.issuerDid || readback.issuerKid !== projection.issuerKid || readback.claims.email !== email
    || readback.credentialDigest !== credential.credentialDigest) {
    throw new CredentialReceiverError("CREDENTIAL_NOT_DURABLE", "The acquired credential was not verified in the active TinyCloud");
  }
  if (result.status === "acquired" && (result.receipt === undefined || result.receipt.recordId !== record.recordId || result.receipt.ownerDid !== record.ownerDid)) {
    throw new CredentialReceiverError("CREDENTIAL_NOT_DURABLE", "The acquired credential has no authenticated storage receipt");
  }
}

function requestedReadCapabilities(share: VerifiedCredentialShare) {
  const envelope = share.envelope;
  if (!envelope.actions.includes("read") || envelope.resource.kind !== "exact"
    || envelope.policyRoot.role !== "policy-authority" || envelope.enforcementRoot.role !== "policy-enforcement"
    || envelope.contentSource.kvResource !== `${envelope.target.spaceId}/kv/${envelope.resource.path}`
    || envelope.contentSource.selector !== "exact" || envelope.contentSource.encryptionNetwork !== envelope.encryptionNetwork) {
    throw new CredentialReceiverError("UNSUPPORTED_REQUIREMENT", "The credential-gated share does not contain one exact read operation");
  }
  return Object.freeze([
    { kind: "kv" as const, resource: envelope.contentSource.kvResource, selector: "exact" as const, actions: ["tinycloud.kv/get" as const] },
    { kind: "encryption" as const, resource: envelope.encryptionNetwork, action: "tinycloud.encryption/decrypt" as const },
  ]);
}

export async function runCredentialReceiver(input: {
  readonly share: VerifiedCredentialShare;
  readonly operation: CredentialShareReadOperation;
  readonly connect: () => Promise<ActiveCredentialClient>;
  readonly openerOrigin: string;
  readonly signal?: AbortSignal;
  readonly onState?: (state: CredentialReceiverState) => void;
}): Promise<CredentialAuthorizedContent> {
  const requirement = credentialRequirementFromVerifiedShare(input.share);
  const projection = await validateCredentialProjectionFromVerifiedShare(input.share, requirement);
  if (input.operation.shareCid !== input.share.shareCid || input.operation.envelope !== input.share.envelope) {
    throw new CredentialReceiverError("INVOCATION_FAILED", "The interrupted share operation was substituted");
  }
  const requestedCapabilities = requestedReadCapabilities(input.share);
  const client = await input.connect();
  const holderDid = client.credentialHolderDid;
  if (client.session() === undefined || !/^did:key:z6Mk[^#]+$/.test(holderDid) || client.credentialHolderKid !== `${holderDid}#${holderDid.slice("did:key:".length)}`) {
    throw new CredentialReceiverError("ACTIVE_SESSION_REQUIRED", "Credential acquisition requires the active TinyCloud/OpenKey session");
  }
  const ensured = await client.credentials.ensure(requirement, {
    descriptor: EMAIL_CREDENTIAL_DESCRIPTOR,
    interaction: "popup",
    openerOrigin: input.openerOrigin,
    ...(input.signal === undefined ? {} : { signal: input.signal }),
    onProgress: (progress) => {
      const state = mapCredentialProgress(progress);
      if (state !== undefined) input.onState?.(state);
    },
  });
  // Popup completion is deliberately not consumed here. `ensure` retrieves
  // and verifies the result through its authenticated channel; Share then
  // proves durable storage by reading the active credentials space again.
  const readback = await client.credentials.find(requirement, {
    descriptor: EMAIL_CREDENTIAL_DESCRIPTOR,
    ...(input.signal === undefined ? {} : { signal: input.signal }),
  });
  assertDurableCredential(ensured, readback, holderDid, requirement.claims.email, projection);

  input.onState?.("authorizing-access");
  let admission: Awaited<ReturnType<ActiveCredentialClient["credentials"]["admitPolicy"]>>;
  try {
    type Policy = Parameters<ActiveCredentialClient["credentials"]["admitPolicy"]>[0]["policy"];
    admission = await client.credentials.admitPolicy({
      ensured,
      policy: input.share.policy as unknown as Policy,
      policyCid: input.share.envelope.policyCid,
      policyRootCid: input.share.envelope.policyRoot.cid,
      enforcementRootCid: input.share.envelope.enforcementRoot.cid,
      requirement,
      requestedCapabilities,
      nodeOrigin: input.share.envelope.target.origin,
    });
    if (admission.installed.cid !== admission.session.cid || admission.installed.audience !== holderDid) {
      throw new Error("installed ordinary delegation binding mismatch");
    }
  } catch (cause) {
    throw receiverError("POLICY_ADMISSION_FAILED", "The verified credential did not authorize this share", cause);
  }

  input.onState?.("opening-content");
  try {
    const envelope = input.operation.envelope;
    const read = await client.kvForSpace(envelope.target.spaceId).get<Uint8Array>(envelope.resource.path, { binary: true, ...(input.signal === undefined ? {} : { signal: input.signal }) });
    if (!read.ok || !ArrayBuffer.isView(read.data.data) || read.data.data.BYTES_PER_ELEMENT !== 1) throw new Error("ordinary KV read failed");
    const encoded = new TextDecoder("utf-8", { fatal: true }).decode(read.data.data);
    const encrypted = JSON.parse(encoded) as unknown;
    if (canonicalize(encrypted) !== encoded) throw new Error("encrypted content is not canonical JSON");
    const decrypted = await client.encryption.decryptEnvelope(encrypted as InlineEncryptedEnvelope, { proofs: [admission.installed.cid] }, { targetNode: envelope.attestedEnforcerBinding.nodeAudience });
    if (!decrypted.ok || !ArrayBuffer.isView(decrypted.data) || decrypted.data.BYTES_PER_ELEMENT !== 1) throw new Error("ordinary delegated decrypt failed");
    const content = Object.freeze({
      type: "TinyCloudCredentialAuthorizedContent" as const,
      version: 1 as const,
      delegationCid: admission.installed.cid,
      bytes: decrypted.data,
      mediaType: envelope.metadata.mediaType ?? "application/octet-stream",
    });
    input.onState?.("success");
    return content;
  } catch (cause) {
    throw receiverError("INVOCATION_FAILED", "TinyCloud could not resume the shared operation", cause);
  }
}

const STATE_COPY: Record<CredentialReceiverState, string> = {
  "checking-existing": "Checking your TinyCloud for this credential…",
  "opening-verification": "Opening email verification…",
  proving: "Confirm your email with the code you received…",
  "waiting-for-approval": "Approve the email binding with your OpenKey…",
  verifying: "Verifying your credential…",
  saving: "Saving the verified credential to your TinyCloud…",
  "authorizing-access": "Email verified. Authorizing this share…",
  "opening-content": "Access granted. Opening the share…",
  success: "Email verified. This credential is now in your TinyCloud.",
};

function element<K extends keyof HTMLElementTagNameMap>(doc: Document, tag: K, className: string, value?: string): HTMLElementTagNameMap[K] {
  const node = doc.createElement(tag);
  node.className = className;
  if (value !== undefined) node.textContent = value;
  return node;
}

export function mountCredentialReceiver(root: HTMLElement, input: {
  readonly share: VerifiedCredentialShare;
  readonly operation: CredentialShareReadOperation;
  readonly connect: () => Promise<ActiveCredentialClient>;
  readonly openerOrigin: string;
  readonly onComplete: (content: CredentialAuthorizedContent) => Promise<void> | void;
}): void {
  const doc = root.ownerDocument;
  const main = element(doc, "main", "viewer-state viewer-claim");
  const status = element(doc, "p", "viewer-state-detail", "Your verified email credential stays in your TinyCloud and can be reused without repeating this flow.");
  status.setAttribute("role", "status");
  status.setAttribute("aria-live", "polite");
  const button = element(doc, "button", "viewer-primary-action", "Confirm email") as HTMLButtonElement;
  button.type = "button";
  main.append(
    element(doc, "h1", "viewer-state-title", "Confirm your email to open this"),
    element(doc, "p", "viewer-state-detail", `This share requires ${credentialRequirementFromVerifiedShare(input.share).claims.email}.`),
    status,
    button,
  );
  root.replaceChildren(main);
  root.setAttribute("tabindex", "-1");
  root.focus();

  button.addEventListener("click", () => {
    button.disabled = true;
    status.textContent = STATE_COPY["checking-existing"];
    void runCredentialReceiver({
      share: input.share,
      operation: input.operation,
      connect: input.connect,
      openerOrigin: input.openerOrigin,
      onState: (state) => { status.textContent = STATE_COPY[state]; },
    }).then(input.onComplete).catch((error: unknown) => {
      console.debug("tinycloud share: credential receiver failed", error);
      button.disabled = false;
      status.setAttribute("role", "alert");
      status.textContent = error instanceof CredentialReceiverError && error.code === "POLICY_ADMISSION_FAILED"
        ? "Email verified and saved, but it didn't grant access to this share. Ask the sender for a new link."
        : error instanceof CredentialReceiverError && error.code === "INVOCATION_FAILED"
          ? "Access was granted, but the share couldn't be opened. Try again."
          : "We couldn't verify and save this email credential. Try again or ask the sender for a new link.";
    });
  });
}
