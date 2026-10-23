import { publishAddressedShare, type AddressedSharePublishOptions } from "@tinycloud/share-sdk";
import { fromBase64Url } from "@tinycloud/share-envelope";
import { ShareTooLargeForLink } from "../short-links/errors.js";
import { LINK_BODY_MAX_BYTES } from "../short-links/limits.js";

/** What the check needs from the owner's session: local signing only, no request to any service. */
export type SealingAuthority = Pick<AddressedSharePublishOptions["authority"], "ownerDid" | "createOwnerRoot" | "sign">;

/** The longest value a node or service returns for each field of a registration receipt. */
const MAX_DIGEST_HEX = "f".repeat(64);
const MAX_SIGNATURE = "A".repeat(86);
const MAX_TIMESTAMP = "9999-12-31T23:59:59.999999999+00:00";

/** Receipt values that exist only after the registration write, at their longest. */
export const MAX_KEY_VERSION = 4_294_967_295;

/**
 * The size in bytes of the sealed body a share would have, before anything is written.
 *
 * It runs the same envelope builder the real publish runs, on the real inputs (path, actions, file name,
 * media type, recipient, expiry), signing locally. Values that exist only after an upload or a
 * registration (the content digests, the key version, the registration receipt) are stood in for by
 * their longest form, so the size measured is at least the size of the real sealed body.
 * The caller builds `options.contentSource` with `maxContentSource`. Makes no request and writes nothing.
 */
export async function measureSealedBody(
  options: Omit<AddressedSharePublishOptions, "authority" | "onDeliveryMaterial">,
  authority: SealingAuthority,
): Promise<number> {
  let sealedBytes = 0;
  await publishAddressedShare({
    ...options,
    onDeliveryMaterial: (material) => { sealedBytes = fromBase64Url(material.sealedEnvelope).byteLength; },
    authority: {
      ...authority,
      registerPolicy: async (input) => ({
        policyCid: input.policyCid,
        policyRootCid: input.policyRoot.cid,
        enforcementRootCid: input.enforcementRoot.cid,
        attestedEnforcerBinding: {
          schema: "xyz.tinycloud.policy/attested-enforcer/v2",
          enforcerDid: input.enforcerDid,
          nodeAudience: input.expectedNodeAudience,
          attestationBindingDigestHex: MAX_DIGEST_HEX,
          issuedAt: MAX_TIMESTAMP,
          expiresAt: MAX_TIMESTAMP,
          signature: { suite: "Ed25519", signerDid: input.expectedNodeAudience, value: MAX_SIGNATURE },
        },
      }),
    },
  });
  return sealedBytes;
}

/** Refuses a share whose sealed body would be over the link size limit, before anything is written. */
export async function assertSealedBodyFits(
  options: Omit<AddressedSharePublishOptions, "authority" | "onDeliveryMaterial">,
  authority: SealingAuthority,
): Promise<void> {
  if ((await measureSealedBody(options, authority)) > LINK_BODY_MAX_BYTES) throw new ShareTooLargeForLink();
}

/** The content source with the values that exist only after the upload at their longest form. */
export function maxContentSource(base: { readonly shareId: string; readonly kvResource: string; readonly selector: "exact" | "prefix"; readonly encryptionNetwork: string }): AddressedSharePublishOptions["contentSource"] {
  return {
    ...base,
    encryptedSymmetricKeyDigestHex: MAX_DIGEST_HEX,
    keyVersion: MAX_KEY_VERSION,
    mode: "immutable",
    initialCiphertextDigestHex: MAX_DIGEST_HEX,
  };
}
