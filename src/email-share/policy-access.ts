/**
 * TC-500 accountless receiver leg.
 *
 * The recipient's browser presents its credential **directly** to the
 * standalone Policy Engine and reads ciphertext through TinyCloud Node's
 * generic capability routes. Nothing here calls a `/share/*` node route: node
 * never sees the credential, the recipient address, the policy decision, or
 * the content key.
 *
 * All of the protocol work lives in `@tinycloud/sdk-core/policy-access`, which
 * is deliberately app-agnostic. This module only supplies Share's own trusted
 * configuration and maps failures onto Share's receiver vocabulary.
 */
import {
  PolicyAccessError,
  createEphemeralHolderKey,
  createFetchPolicyAccessTransport,
  decryptLocally,
  openPolicyAccess,
  type EphemeralHolderKey,
  type PolicyAccessSession,
  type PolicyAccessTransport,
} from "@tinycloud/sdk-core/policy-access";
import type { InvokeFunction } from "@tinycloud/sdk-services";
import { sha256 } from "@noble/hashes/sha256";
import { ENVELOPE_AAD_LABEL, SEALED_BLOB_VERSION, toBase64Url } from "@tinycloud/share-envelope";
import type { SharePublicConfig } from "./config.js";

/**
 * Policy-gated bodies are sealed with the same primitive as every other Share
 * blob (`seal()` from `@tinycloud/share-envelope`): one version byte, a 12-byte
 * nonce, then AES-256-GCM bound to the envelope AAD label. Decrypting with the
 * SDK's generic `decryptLocally` therefore has to supply that AAD, or a blob
 * the sender sealed correctly would fail authentication and look like a wrong
 * key.
 */
const SEALED_BODY_AAD = new TextEncoder().encode(ENVELOPE_AAD_LABEL);

export interface SharePolicyEngineBinding {
  readonly endpoint: string;
  readonly audience: string;
  readonly grantIssuerDid: string;
}

/**
 * Reads the Policy Engine binding out of the verified public config.
 *
 * Returns `undefined` when the deployment has not enrolled a Policy Engine
 * yet, which is the signal to keep using the legacy Node-brokered receiver
 * rather than to invent an endpoint.
 */
export function policyEngineBindingFromConfig(
  config: SharePublicConfig,
): SharePolicyEngineBinding | undefined {
  if (
    config.policyEngineOrigin === undefined ||
    config.policyEngineAudience === undefined ||
    config.policyEngineGrantIssuerDid === undefined
  ) {
    return undefined;
  }
  return Object.freeze({
    endpoint: config.policyEngineOrigin,
    audience: config.policyEngineAudience,
    grantIssuerDid: config.policyEngineGrantIssuerDid,
  });
}

/**
 * Every origin the accountless receiver may contact, built from Share's own
 * verified config. Invitation bytes never contribute an origin.
 */
export function receiverOriginPolicy(
  config: SharePublicConfig,
  binding: SharePolicyEngineBinding,
): { readonly allowedOrigins: readonly string[] } {
  return {
    allowedOrigins: [
      config.credentialsOrigin,
      config.nodeOrigin,
      binding.endpoint,
    ],
  };
}

export interface ShareAccountlessReadInput {
  readonly config: SharePublicConfig;
  readonly binding: SharePolicyEngineBinding;
  /** Policy the sender registered with the engine for this share. */
  readonly policyId: string;
  /** Capability-model space for the owner's TinyCloud space. */
  readonly capabilitySpace: string;
  /** Node-side space id used for the delegation import receipt. */
  readonly nodeSpaceId: string;
  /** Exact KV path holding the encrypted share body. */
  readonly resourcePath: string;
  /** Evidence requirement id the sender's policy declares. */
  readonly requirementId: string;
  /** The `vc+sd-jwt` credential the recipient just acquired. */
  readonly credential: string;
  /** Content key the recipient unwrapped locally. */
  readonly contentKey: Uint8Array;
  /** SHA-256 of the stored ciphertext, bound into the signed envelope. */
  readonly expectedCiphertextDigest: string;
  readonly holder: EphemeralHolderKey;
  readonly invoke: InvokeFunction;
  readonly transport?: PolicyAccessTransport;
}

export interface ShareAccountlessReadResult {
  readonly plaintext: Uint8Array;
  readonly session: PolicyAccessSession;
}

/** A fresh tab-scoped key. Closing the tab ends access even before expiry. */
export function createReceiverHolder(): EphemeralHolderKey {
  return createEphemeralHolderKey();
}

/**
 * Present, delegate, read, and decrypt. The returned session is short-lived
 * and holder-bound; callers should discard it rather than persist it.
 */
export async function readAccountlessShare(
  input: ShareAccountlessReadInput,
): Promise<ShareAccountlessReadResult> {
  const transport =
    input.transport ??
    createFetchPolicyAccessTransport({
      originPolicy: receiverOriginPolicy(input.config, input.binding),
    });

  const session = await openPolicyAccess({
    descriptor: {
      policyId: input.policyId,
      policyEngine: {
        endpoint: input.binding.endpoint,
        audience: input.binding.audience,
        grantIssuerDid: input.binding.grantIssuerDid,
      },
      ownerNode: {
        endpoint: input.config.nodeOrigin,
        spaceId: input.nodeSpaceId,
      },
      requestedCapabilities: [
        {
          service: "tinycloud.kv",
          space: input.capabilitySpace,
          path: input.resourcePath,
          actions: ["tinycloud.kv/get"],
        },
      ],
    },
    holder: input.holder,
    transport,
    evidence: [
      {
        requirementId: input.requirementId,
        presentation: { sdJwt: input.credential },
      },
    ],
    invoke: input.invoke,
  });

  const { ciphertext } = await session.readEncrypted(input.resourcePath);
  const ciphertextDigest = toBase64Url(sha256(ciphertext));
  if (ciphertextDigest !== input.expectedCiphertextDigest) {
    throw new PolicyAccessError(
      "decrypt-failed",
      "stored ciphertext does not match the signed envelope",
    );
  }
  const plaintext = await decryptLocally({
    ciphertext,
    key: input.contentKey,
    versionByte: SEALED_BLOB_VERSION,
    aad: SEALED_BODY_AAD,
  });
  return { plaintext, session };
}

export { PolicyAccessError };
export type { EphemeralHolderKey, PolicyAccessSession, PolicyAccessTransport };
