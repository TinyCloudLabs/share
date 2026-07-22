import {
  canonicalEmail,
  canonicalDigest,
  createInvitationDraft,
  validateSource,
  type ContentSource,
  type InvitationDraft,
  type SenderScope,
  type ShareAction,
} from "../../../src/email-share/protocol.js";
import { validateShareAuthority } from "../../../src/email-share/authority-verifier.js";
import {
  canonicalize,
  didKeyFromEd25519PublicKey,
  isCanonicalHttpsOrigin,
  isCanonicalPathSegment,
  parseShareUrl,
  shareEnvelopeSchema,
  targetSchema,
} from "@tinycloud/share-envelope";

declare const generatedShareLinkBrand: unique symbol;

export interface ShareLinkTarget {
  readonly origin: string;
  readonly nodeAudience: string;
  readonly spaceId: string;
}

/** The complete authoritative policy contract required before a link is uploaded. */
export interface ShareLinkPolicy {
  readonly recipientEmail: string;
  readonly source: ContentSource;
  readonly action: ShareAction;
  readonly resource: string;
  readonly expiresAt: string;
  readonly target: ShareLinkTarget;
  readonly policyCid: string;
  readonly policyDigest: string;
  readonly contentSourceDigest: string;
  readonly delegationCid: string;
  readonly authorityMaterialDigest: string;
  readonly policyBytes: string;
  readonly policyAuthorityCid: string;
  readonly policyAuthorityBytes: string;
  readonly policyEnforcementCid: string;
  readonly policyEnforcementBytes: string;
}

export interface GeneratedShareLinkProvenance extends ShareLinkPolicy {
  readonly shareOrigin: string;
  readonly shareId: string;
  readonly shareCid: string;
  readonly policyCid: string;
  readonly policyDigest: string;
  readonly contentSourceDigest: string;
  readonly senderDid: string;
  readonly delegationCid: string;
  readonly authorityMaterialHandle: SenderScope["authorityMaterialHandle"];
  readonly authorityMaterialDigest: string;
  readonly policyAuthorityCid: string;
  readonly policyEnforcementCid: string;
}

export interface GeneratedShareLink {
  readonly [generatedShareLinkBrand]: true;
  readonly shareUrl: string;
  readonly shareCid: string;
  readonly shareId: string;
  readonly policyCid: string;
  readonly policyDigest: string;
  readonly recipientEmail: string;
  readonly source: ContentSource;
  readonly action: ShareAction;
  readonly resource: string;
  readonly expiresAt: string;
  readonly target: ShareLinkTarget;
  readonly provenance: GeneratedShareLinkProvenance;
}

export type ShareArtifact = GeneratedShareLink;

export interface ShareLinkAdapters {
  readonly uploadEnvelope: (cid: string, blob: Uint8Array, deleteAfter: string) => Promise<void>;
  readonly publishBinding?: (binding: Record<string, unknown>) => Promise<void>;
}

export interface CreateShareLinkInput {
  readonly email: string;
  readonly source: ContentSource;
  readonly scope: SenderScope;
  readonly shareId: string;
  readonly expiresAt: string;
  readonly policy: ShareLinkPolicy;
  readonly target?: ShareLinkTarget;
  readonly adapters: ShareLinkAdapters;
  readonly now?: string;
}

const drafts = new WeakMap<object, InvitationDraft>();
const provenances = new WeakMap<object, GeneratedShareLinkProvenance>();

function freezeValue<T>(value: T): T {
  if (typeof value !== "object" || value === null || Object.isFrozen(value)) return value;
  for (const child of Object.values(value as Record<string, unknown>)) freezeValue(child);
  return Object.freeze(value);
}

function sameValue(actual: unknown, expected: unknown): boolean {
  return typeof actual === "object" || typeof expected === "object" ? canonicalize(actual) === canonicalize(expected) : actual === expected;
}

function targetFor(scope: SenderScope): ShareLinkTarget {
  return { origin: scope.targetOrigin, nodeAudience: scope.nodeAudience, spaceId: scope.spaceId };
}

function assertTarget(target: ShareLinkTarget, expected: ShareLinkTarget): void {
  if (!sameValue(target, expected)) throw new TypeError("The share target does not match the authenticated scope.");
}

async function normalizedSource(source: ContentSource): Promise<ContentSource> {
  const validated = validateSource(source);
  return validated.kind === "sql" ? { ...validated, argumentsDigest: await canonicalDigest(validated.arguments) } : validated;
}

function assertGenerationInputs(input: { readonly shareId: string; readonly expiresAt: string; readonly scope: SenderScope }, email: string, source: ContentSource, now: string): void {
  if (typeof input.shareId !== "string" || !/^[^\u0000-\u001f\u007f]{1,200}$/.test(input.shareId)) throw new TypeError("shareId is not canonical.");
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(now) || !Number.isFinite(Date.parse(now))) throw new TypeError("now must be canonical UTC.");
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(input.expiresAt) || !Number.isFinite(Date.parse(input.expiresAt)) || Date.parse(input.expiresAt) <= Date.parse(now)) throw new TypeError("Choose an access expiry within the allowed policy window.");
  if (input.scope.spaceId !== source.space || !isCanonicalPathSegment(input.scope.spaceId)) throw new TypeError("The selected resource is outside the authorized space.");
  if (!isCanonicalHttpsOrigin(input.scope.shareOrigin) || !isCanonicalHttpsOrigin(input.scope.targetOrigin) || input.scope.trustedNode.targetOrigin !== input.scope.targetOrigin) throw new TypeError("Share and target origins must be canonical HTTPS origins.");
  if (input.scope.trustedNode.nodeAudience !== input.scope.nodeAudience || input.scope.nodeAudience.length === 0 || input.scope.trustedNode.invitationPublicKey.length !== 32 || !input.scope.trustedNode.enabled) throw new TypeError("The authenticated target is not trusted.");
  if (input.scope.signingCapability.publicKey.length !== 32 || input.scope.signer.publicKey.length !== 32 || input.scope.signingCapability.publicKey.some((byte, index) => byte !== input.scope.signer.publicKey[index])) throw new TypeError("The sender signing capability does not match the signer.");
  if (didKeyFromEd25519PublicKey(input.scope.signer.publicKey) !== input.scope.senderDid) throw new TypeError("The sender provenance does not match the authenticated signer.");
  if (source.action !== (source.kind === "kv" ? "tinycloud.kv/get" : "tinycloud.sql/read")) throw new TypeError("The source action is invalid.");
  if (email !== canonicalEmail(email)) throw new TypeError("The recipient email is not canonical.");
  const expiry = Date.parse(input.expiresAt);
  for (const value of [input.scope.expiryMin, input.scope.expiryMax, input.scope.expiresAt]) if (value !== undefined && (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value) || !Number.isFinite(Date.parse(value)))) throw new TypeError("Authenticated expiry bounds must be canonical UTC.");
  if (input.scope.expiryMin !== undefined && expiry < Date.parse(input.scope.expiryMin)) throw new TypeError("The requested expiry is below the authenticated policy minimum.");
  if ([input.scope.expiryMax, input.scope.expiresAt].filter((value): value is string => value !== undefined).map(Date.parse).some((bound) => expiry > bound)) throw new TypeError("The requested expiry exceeds the authenticated policy maximum.");
  targetSchema.parse({ origin: input.scope.targetOrigin, nodeAudience: input.scope.nodeAudience, spaceId: input.scope.spaceId, resource: { kind: "exact", path: source.path } });
}

function provenanceFor(draft: InvitationDraft, scope: SenderScope, validation: Awaited<ReturnType<typeof validateShareAuthority>>): GeneratedShareLinkProvenance {
  return {
    recipientEmail: draft.email, source: draft.source, action: draft.source.action, resource: draft.source.path, expiresAt: draft.envelope.expiry, target: targetFor(scope), shareOrigin: scope.shareOrigin,
    shareId: draft.envelope.shareId, shareCid: draft.shareCid, policyCid: draft.policyCid, policyDigest: validation.policyDigest, policyBytes: validation.policyBytes, contentSourceDigest: draft.sourceDigest,
    senderDid: scope.senderDid, delegationCid: scope.delegationCid, authorityMaterialHandle: scope.authorityMaterialHandle, authorityMaterialDigest: scope.authorityMaterialDigest,
    policyAuthorityCid: validation.policyAuthorityCid, policyAuthorityBytes: validation.policyAuthorityBytes, policyEnforcementCid: validation.policyEnforcementCid, policyEnforcementBytes: validation.policyEnforcementBytes,
  };
}

function artifactFor(draft: InvitationDraft, scope: SenderScope, validation: Awaited<ReturnType<typeof validateShareAuthority>>): GeneratedShareLink {
  const source = freezeValue({ ...draft.source });
  const target = freezeValue(targetFor(scope));
  const provenance = freezeValue({ ...provenanceFor(draft, scope, validation), source, target });
  const artifact = Object.freeze({ shareUrl: draft.shareUrl, shareCid: draft.shareCid, shareId: draft.envelope.shareId, policyCid: draft.policyCid, policyDigest: validation.policyDigest, recipientEmail: draft.email, source, action: draft.source.action, resource: draft.source.path, expiresAt: draft.envelope.expiry, target, provenance });
  drafts.set(artifact, draft);
  provenances.set(artifact, provenance);
  return artifact as GeneratedShareLink;
}

export function assertGeneratedShareLink(value: GeneratedShareLink): void {
  const draft = drafts.get(value as object);
  const provenance = provenances.get(value as object);
  if (draft === undefined || provenance === undefined || value.shareUrl !== draft.shareUrl || value.shareCid !== draft.shareCid || value.shareId !== draft.envelope.shareId || value.policyCid !== draft.policyCid || value.policyDigest !== provenance.policyDigest || value.recipientEmail !== draft.email || !sameValue(value.source, draft.source) || value.action !== draft.source.action || value.resource !== draft.source.path || value.expiresAt !== draft.envelope.expiry || !sameValue(value.target, provenance.target) || !sameValue(value.provenance, provenance)) throw new TypeError("The share artifact is not a generated exact-email link.");
  if (parseShareUrl(value.shareUrl, { expectedOrigin: provenance.shareOrigin }).ciphertextCid !== value.shareCid) throw new TypeError("The generated share link was substituted.");
}

/** Creates, seals, uploads, and returns a policy-bound share link. It never sends email or reads content. */
export async function createShareLink(input: CreateShareLinkInput): Promise<GeneratedShareLink> {
  if (typeof input.adapters?.uploadEnvelope !== "function") throw new TypeError("An envelope upload adapter is required.");
  const email = canonicalEmail(input.email);
  const source = await normalizedSource(input.source);
  const now = input.now ?? new Date().toISOString();
  assertGenerationInputs(input, email, source, now);
  const validation = await validateShareAuthority({ policy: input.policy, email, source, scope: input.scope, expiresAt: input.expiresAt, now });
  if (input.target !== undefined) assertTarget(input.target, targetFor(input.scope));
  const draft = await createInvitationDraft({ email, source, scope: input.scope, shareId: input.shareId, expiresAt: input.expiresAt, policy: { policyCid: validation.policyCid, policyBytes: validation.policyBytes, policyDigest: validation.policyDigest, policyAuthorityCid: validation.policyAuthorityCid, policyAuthorityBytes: validation.policyAuthorityBytes, policyEnforcementCid: validation.policyEnforcementCid, policyEnforcementBytes: validation.policyEnforcementBytes }, uploadEnvelope: input.adapters.uploadEnvelope, now });
  await input.adapters.publishBinding?.({ capabilityId: input.scope.signingCapability.capabilityId, shareId: draft.envelope.shareId, shareCid: draft.shareCid, policyCid: draft.policyCid, policyDigest: validation.policyDigest, policyBytes: validation.policyBytes, recipientEmail: draft.email, expiry: draft.envelope.expiry, delegationCid: input.scope.delegationCid, authorityMaterialHandle: input.scope.authorityMaterialHandle, authorityMaterialDigest: input.scope.authorityMaterialDigest, policyAuthorityCid: validation.policyAuthorityCid, policyAuthorityBytes: validation.policyAuthorityBytes, policyEnforcementCid: validation.policyEnforcementCid, policyEnforcementBytes: validation.policyEnforcementBytes, contentSource: draft.source, contentSourceDigest: draft.sourceDigest, action: draft.source.action, resource: draft.source.path, target: targetFor(input.scope), returnOrigin: input.scope.shareOrigin });
  return artifactFor(draft, input.scope, validation);
}

export function draftForGeneratedShareLink(value: GeneratedShareLink): InvitationDraft {
  const draft = drafts.get(value as object);
  const provenance = provenances.get(value as object);
  assertGeneratedShareLink(value);
  if (draft === undefined || provenance === undefined) throw new TypeError("The share artifact is not a generated exact-email link.");
  return draft;
}
