import { ed25519 } from "@noble/curves/ed25519";
import { blake3 } from "@noble/hashes/blake3";
import { keccak_256 } from "@noble/hashes/sha3";
import { CID } from "multiformats/cid";
import * as raw from "multiformats/codecs/raw";
import * as digest from "multiformats/hashes/digest";
import { z } from "zod";

import { fromBase64Url, utf8Bytes } from "./bytes.js";
import {
  canonicalNodeAudienceForOrigin,
  isCanonicalDeploymentNodeAudience,
} from "./deployment-origin.js";
import { didKeyFromEd25519PublicKey, ed25519PublicKeyFromDidKey } from "./didkey.js";
import { canonicalize } from "./jcs.js";
import { displaySchema, isCanonicalHttpsOrigin, isCanonicalResourcePath } from "./schema.js";

export {
  canonicalNodeAudienceForOrigin,
  isCanonicalDeploymentNodeAudience,
} from "./deployment-origin.js";

export const RECIPIENT_DID_V2_SIGNATURE_DOMAIN = "xyz.tinycloud.share/envelope/v2\0";
export const TINYCLOUD_DELEGATION_CID_MULTIHASH = 0x1e;
const ED25519_VERIFY_OPTS = { zip215: false } as const;
const MAINNET_PKH_RE = /^did:pkh:eip155:1:(0x[0-9a-fA-F]{40})$/;
const MAINNET_SPACE_RE = /^tinycloud:pkh:eip155:1:(0x[0-9a-fA-F]{40}):([A-Za-z0-9_-]+)$/;

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

/** Exact chain-1/EIP-55 behavior of sdk-core's `canonicalizeDid`. */
export function canonicalMainnetPkhDid(did: string): string | null {
  const match = did.match(MAINNET_PKH_RE);
  const address = match?.[1];
  if (address === undefined) return null;
  const lower = address.slice(2).toLowerCase();
  const checksumHash = hex(keccak_256(utf8Bytes(lower)));
  let checksummed = "0x";
  for (let index = 0; index < lower.length; index++) {
    const char = lower[index];
    const nibble = checksumHash[index];
    if (char === undefined || nibble === undefined) return null;
    checksummed += /[a-f]/.test(char) && Number.parseInt(nibble, 16) >= 8
      ? char.toUpperCase()
      : char;
  }
  return `did:pkh:eip155:1:${checksummed}`;
}

export function isCanonicalMainnetPkhDid(did: string): boolean {
  return canonicalMainnetPkhDid(did) === did;
}

export function ownerDidFromCanonicalSpaceId(spaceId: string): string | null {
  const match = spaceId.match(MAINNET_SPACE_RE);
  const address = match?.[1];
  if (address === undefined) return null;
  const canonicalDid = canonicalMainnetPkhDid(`did:pkh:eip155:1:${address}`);
  return canonicalDid === `did:pkh:eip155:1:${address}` ? canonicalDid : null;
}

export function isCanonicalMainnetSpaceId(spaceId: string): boolean {
  return ownerDidFromCanonicalSpaceId(spaceId) !== null;
}

/** Strict canonical Ed25519 did:key, including multicodec, length, and point decoding. */
export function isCanonicalEd25519DidKey(did: string): boolean {
  try {
    const publicKey = ed25519PublicKeyFromDidKey(did);
    const point = ed25519.Point.fromBytes(publicKey);
    point.assertValidity();
    if (point.isSmallOrder() || !point.isTorsionFree()) return false;
    if (!point.toBytes().every((byte, index) => byte === publicKey[index])) return false;
    return didKeyFromEd25519PublicKey(publicKey) === did;
  } catch {
    return false;
  }
}

/** Current SDK verification method: `did:key:<multibase>#<same multibase>`. */
export function principalFromSessionVerificationMethod(value: string): string | null {
  const match = value.match(/^(did:key:(z[1-9A-HJ-NP-Za-km-z]+))#(z[1-9A-HJ-NP-Za-km-z]+)$/);
  if (match === null || match[1] === undefined || match[2] === undefined || match[3] === undefined) {
    return null;
  }
  if (match[2] !== match[3] || !isCanonicalEd25519DidKey(match[1])) return null;
  return match[1];
}

export function isCanonicalDelegationCid(cidText: string): boolean {
  try {
    const cid = CID.parse(cidText);
    return cid.version === 1 && cid.code === raw.code &&
      cid.multihash.code === TINYCLOUD_DELEGATION_CID_MULTIHASH &&
      cid.multihash.size === 32 &&
      cid.toString() === cidText;
  } catch {
    return false;
  }
}

function decodeCanonicalPaddedBase64Url(value: string): Uint8Array | null {
  if (!/^[A-Za-z0-9_-]+={0,2}$/.test(value) || value.length % 4 !== 0) return null;
  const unpadded = value.replace(/=+$/, "");
  try {
    const bytes = fromBase64Url(unpadded);
    const requiredPadding = "=".repeat((4 - (unpadded.length % 4)) % 4);
    return `${unpadded}${requiredPadding}` === value ? bytes : null;
  } catch {
    return null;
  }
}

function isCanonicalUcanJwt(value: string): boolean {
  const segments = value.split(".");
  if (segments.length !== 3) return false;
  return segments.every((segment) => {
    if (segment.length === 0 || segment.includes("=")) return false;
    try {
      return fromBase64Url(segment).length > 0;
    } catch {
      return false;
    }
  });
}

const canonicalDelegationCidSchema = z.string().refine(isCanonicalDelegationCid, {
  message: "expected canonical CIDv1/raw/blake3-256",
});

export const cacaoDelegationArtifactV2Schema = z.object({
  kind: z.literal("cacao"),
  cid: canonicalDelegationCidSchema,
  encoding: z.literal("dag-cbor-base64url-pad"),
  /** Current TinyCloud HeaderEncode output: padded URL-safe base64 of DAG-CBOR bytes. */
  value: z.string().refine((value) => decodeCanonicalPaddedBase64Url(value) !== null, {
    message: "expected canonical padded base64url DAG-CBOR transport",
  }),
}).strict();

export const ucanDelegationArtifactV2Schema = z.object({
  kind: z.literal("ucan"),
  cid: canonicalDelegationCidSchema,
  encoding: z.literal("jwt"),
  /** Current TinyCloud UCAN transport: exactly three canonical unpadded base64url segments. */
  value: z.string().refine(isCanonicalUcanJwt, { message: "expected canonical UCAN JWT" }),
}).strict();

export const delegationArtifactV2Schema = z.discriminatedUnion("kind", [
  cacaoDelegationArtifactV2Schema,
  ucanDelegationArtifactV2Schema,
]);

export const recipientDidDelegationRoutingV2Schema = z.object({
  origin: z.string().refine(isCanonicalHttpsOrigin, "expected canonical HTTPS origin"),
  nodeAudience: z.string().refine(isCanonicalDeploymentNodeAudience, "expected canonical deployment did:web"),
}).strict().superRefine((routing, ctx) => {
  if (canonicalNodeAudienceForOrigin(routing.origin) !== routing.nodeAudience) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["nodeAudience"], message: "node audience must exactly derive from origin host" });
  }
});

export const recipientDidDelegationBundleV2Schema = z.object({
  format: z.literal("tinycloud-recipient-delegation-v2"),
  routing: recipientDidDelegationRoutingV2Schema,
  grant: ucanDelegationArtifactV2Schema,
  /** Root-to-leaf: one owner Cacao followed by zero or more UCAN session proofs. */
  issuerProofs: z.array(delegationArtifactV2Schema).min(1).max(8),
}).strict().superRefine((bundle, ctx) => {
  if (bundle.issuerProofs[0]?.kind !== "cacao" || bundle.issuerProofs.slice(1).some((p) => p.kind !== "ucan")) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["issuerProofs"], message: "expected Cacao root followed only by UCAN proofs" });
  }
  const cids = [bundle.grant.cid, ...bundle.issuerProofs.map((proof) => proof.cid)];
  if (new Set(cids).size !== cids.length) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["issuerProofs"], message: "every artifact CID must occur exactly once" });
  }
});

export type CacaoDelegationArtifactV2 = z.infer<typeof cacaoDelegationArtifactV2Schema>;
export type UcanDelegationArtifactV2 = z.infer<typeof ucanDelegationArtifactV2Schema>;
export type DelegationArtifactV2 = z.infer<typeof delegationArtifactV2Schema>;
export type RecipientDidDelegationBundleV2 = z.infer<typeof recipientDidDelegationBundleV2Schema>;

export function delegationArtifactCidPreimage(artifact: DelegationArtifactV2): Uint8Array {
  const parsed = delegationArtifactV2Schema.parse(artifact);
  if (parsed.kind === "cacao") {
    const bytes = decodeCanonicalPaddedBase64Url(parsed.value);
    if (bytes === null) throw new TypeError("invalid Cacao transport");
    return bytes;
  }
  return utf8Bytes(parsed.value);
}

export function computeDelegationArtifactCid(artifact: DelegationArtifactV2): string {
  const multihash = digest.create(
    TINYCLOUD_DELEGATION_CID_MULTIHASH,
    blake3(delegationArtifactCidPreimage(artifact)),
  );
  return CID.create(1, raw.code, multihash).toString();
}

const recipientDidV2TargetObjectSchema = z.object({
  origin: z.string().refine(isCanonicalHttpsOrigin, "expected canonical HTTPS origin"),
  nodeAudience: z.string().refine(isCanonicalDeploymentNodeAudience, "expected canonical deployment did:web"),
  spaceId: z.string().refine(isCanonicalMainnetSpaceId, "expected canonical mainnet PKH space ID"),
  resource: z.object({
    kind: z.literal("exact"),
    path: z.string().refine(isCanonicalResourcePath, "expected canonical exact path"),
  }).strict(),
  actions: z.array(z.string().regex(/^tinycloud\.[a-z0-9-]+\/[a-z0-9*_-]+$/)).min(1)
    .superRefine((actions, ctx) => {
      const canonical = [...new Set(actions)].sort();
      if (canonical.length !== actions.length || canonical.some((value, i) => value !== actions[i])) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, message: "actions must be unique and sorted" });
      }
    }),
}).strict();

const recipientDidV2TargetSchema = recipientDidV2TargetObjectSchema.superRefine((target, ctx) => {
  if (canonicalNodeAudienceForOrigin(target.origin) !== target.nodeAudience) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["nodeAudience"], message: "node audience must exactly derive from origin host" });
  }
});

const canonicalExpirySchema = z.string().datetime().refine(
  (value) => new Date(value).toISOString() === value,
  "expected canonical UTC ISO time",
);

const recipientDidEnvelopeV2BodyFields = {
  version: z.literal(2),
  shareId: z.string().min(1),
  delegation: recipientDidDelegationBundleV2Schema,
  authorizationTarget: z.object({
    kind: z.literal("recipientDid"),
    did: z.string().refine(isCanonicalMainnetPkhDid, "expected canonical mainnet did:pkh"),
  }).strict(),
  target: recipientDidV2TargetSchema,
  display: displaySchema,
  expiry: canonicalExpirySchema,
};

export const unsignedRecipientDidEnvelopeV2Schema = z.object(recipientDidEnvelopeV2BodyFields).strict();
const signerDidSchema = z.string().refine(isCanonicalEd25519DidKey, "expected canonical Ed25519 did:key");
export const recipientDidEnvelopeV2SignatureMetadataSchema = z.object({
  signerDid: signerDidSchema,
  algorithm: z.literal("Ed25519"),
}).strict();
export const recipientDidEnvelopeV2SigningPayloadSchema = z.object({
  ...recipientDidEnvelopeV2BodyFields,
  signature: recipientDidEnvelopeV2SignatureMetadataSchema,
}).strict();
export const recipientDidEnvelopeV2Schema = recipientDidEnvelopeV2SigningPayloadSchema.extend({
  signature: recipientDidEnvelopeV2SignatureMetadataSchema.extend({
    value: z.string().refine((value) => {
      try { return fromBase64Url(value).length === 64; } catch { return false; }
    }, "expected canonical unpadded base64url encoding exactly 64 bytes"),
  }).strict(),
}).strict();

export type UnsignedRecipientDidEnvelopeV2 = z.infer<typeof unsignedRecipientDidEnvelopeV2Schema>;
export type RecipientDidEnvelopeV2SigningPayload = z.infer<typeof recipientDidEnvelopeV2SigningPayloadSchema>;
export type RecipientDidEnvelopeV2 = z.infer<typeof recipientDidEnvelopeV2Schema>;

function concatBytes(left: Uint8Array, right: Uint8Array): Uint8Array {
  const output = new Uint8Array(left.length + right.length);
  output.set(left); output.set(right, left.length);
  return output;
}

export function recipientDidEnvelopeV2SigningBytes(payload: RecipientDidEnvelopeV2SigningPayload): Uint8Array {
  const parsed = recipientDidEnvelopeV2SigningPayloadSchema.parse(payload);
  return concatBytes(utf8Bytes(RECIPIENT_DID_V2_SIGNATURE_DOMAIN), utf8Bytes(canonicalize(parsed)));
}

/** Verification is total for untrusted input: malformed DID/key/signature data returns false. */
export function verifyRecipientDidEnvelopeV2Signature(input: unknown): boolean {
  const result = recipientDidEnvelopeV2Schema.safeParse(input);
  if (!result.success) return false;
  try {
    const { value, ...metadata } = result.data.signature;
    return ed25519.verify(
      fromBase64Url(value),
      recipientDidEnvelopeV2SigningBytes({ ...result.data, signature: metadata }),
      ed25519PublicKeyFromDidKey(metadata.signerDid),
      ED25519_VERIFY_OPTS,
    );
  } catch {
    return false;
  }
}

const verifiedScopeSchema = recipientDidV2TargetObjectSchema.omit({ origin: true, nodeAudience: true }).strict();
export const nativeVerifiedRecipientBundleV2Schema = z.object({
  verification: z.literal("tinycloud-native-authority-v1"),
  ownerDid: z.string().refine(isCanonicalMainnetPkhDid),
  sessionPrincipalDid: signerDidSchema,
  sessionVerificationMethod: z.string().refine(
    (value) => principalFromSessionVerificationMethod(value) !== null,
    "expected current SDK did:key verification method fragment",
  ),
  recipientDid: z.string().refine(isCanonicalMainnetPkhDid),
  grantCid: canonicalDelegationCidSchema,
  proofCids: z.array(canonicalDelegationCidSchema).min(1).max(8),
  scope: verifiedScopeSchema,
  notBefore: canonicalExpirySchema.optional(),
  expiry: canonicalExpirySchema,
}).strict();

export type NativeVerifiedRecipientBundleV2 = z.infer<typeof nativeVerifiedRecipientBundleV2Schema>;

export interface VerifyRecipientDidEnvelopeV2Options {
  allowedOrigins: readonly string[];
  /**
   * One atomic native operation. Success means all artifact signatures and CIDs,
   * SIWE ReCap authority, every edge's audience/proof/attenuation/time, and the
   * complete root-to-grant chain were verified together without network discovery.
   */
  verifyDelegationBundle(
    bundle: RecipientDidDelegationBundleV2,
    now: Date,
  ): Promise<NativeVerifiedRecipientBundleV2>;
  now?: Date;
  /** Test/diagnostic hook for the security-critical verification order. */
  onStage?: (stage: RecipientDidEnvelopeV2VerificationStage) => void;
}

export type RecipientDidEnvelopeV2VerificationStage =
  | "schema"
  | "artifact-structure"
  | "envelope-signature"
  | "native-authority"
  | "static-routing"
  | "authority-binding"
  | "time";

export type RecipientDidEnvelopeV2RejectCode =
  | "schema" | "origin-not-allowed" | "artifact-cid-mismatch" | "delegation-invalid"
  | "authority-mismatch" | "signature" | "recipient-mismatch" | "target-mismatch"
  | "expiry-mismatch" | "expired";
export type RecipientDidEnvelopeV2Verification =
  | { ok: true; envelope: RecipientDidEnvelopeV2; ownerDid: string }
  | { ok: false; code: RecipientDidEnvelopeV2RejectCode };

function sameStrings(left: readonly string[], right: readonly string[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

export async function verifyRecipientDidEnvelopeV2(
  input: unknown,
  options: VerifyRecipientDidEnvelopeV2Options,
): Promise<RecipientDidEnvelopeV2Verification> {
  const parsed = recipientDidEnvelopeV2Schema.safeParse(input);
  if (!parsed.success) return { ok: false, code: "schema" };
  const envelope = parsed.data;
  options.onStage?.("schema");
  const artifacts: DelegationArtifactV2[] = [
    envelope.delegation.grant,
    ...envelope.delegation.issuerProofs,
  ];
  if (artifacts.some((artifact) => computeDelegationArtifactCid(artifact) !== artifact.cid)) {
    return { ok: false, code: "artifact-cid-mismatch" };
  }
  options.onStage?.("artifact-structure");
  if (!verifyRecipientDidEnvelopeV2Signature(envelope)) {
    return { ok: false, code: "signature" };
  }
  options.onStage?.("envelope-signature");
  const now = options.now ?? new Date();
  let authority: NativeVerifiedRecipientBundleV2;
  try {
    options.onStage?.("native-authority");
    authority = nativeVerifiedRecipientBundleV2Schema.parse(
      await options.verifyDelegationBundle(envelope.delegation, now),
    );
  } catch {
    return { ok: false, code: "delegation-invalid" };
  }
  options.onStage?.("static-routing");
  if (!options.allowedOrigins.includes(envelope.target.origin)) {
    return { ok: false, code: "origin-not-allowed" };
  }
  if (
    envelope.delegation.routing.origin !== envelope.target.origin ||
    envelope.delegation.routing.nodeAudience !== envelope.target.nodeAudience
  ) {
    return { ok: false, code: "target-mismatch" };
  }
  const proofCids = envelope.delegation.issuerProofs.map((proof) => proof.cid);
  const spaceOwner = ownerDidFromCanonicalSpaceId(envelope.target.spaceId);
  if (
    spaceOwner === null || authority.ownerDid !== spaceOwner ||
    authority.grantCid !== envelope.delegation.grant.cid ||
    !sameStrings(authority.proofCids, proofCids) ||
    authority.sessionPrincipalDid !== envelope.signature.signerDid ||
    principalFromSessionVerificationMethod(authority.sessionVerificationMethod) !== authority.sessionPrincipalDid
  ) {
    return { ok: false, code: "authority-mismatch" };
  }
  if (authority.recipientDid !== envelope.authorizationTarget.did) {
    return { ok: false, code: "recipient-mismatch" };
  }
  if (
    authority.scope.spaceId !== envelope.target.spaceId ||
    authority.scope.resource.kind !== envelope.target.resource.kind ||
    authority.scope.resource.path !== envelope.target.resource.path ||
    !sameStrings(authority.scope.actions, envelope.target.actions)
  ) {
    return { ok: false, code: "target-mismatch" };
  }
  options.onStage?.("authority-binding");
  if (authority.expiry !== envelope.expiry) return { ok: false, code: "expiry-mismatch" };
  const nowMs = now.getTime();
  if (authority.notBefore !== undefined && new Date(authority.notBefore).getTime() > nowMs) {
    return { ok: false, code: "delegation-invalid" };
  }
  if (new Date(envelope.expiry).getTime() <= nowMs) return { ok: false, code: "expired" };
  options.onStage?.("time");
  return { ok: true, envelope, ownerDid: authority.ownerDid };
}
