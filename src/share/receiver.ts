import { fromBase64Url } from "@tinycloud/share-envelope";
import { TinyCloudWeb } from "@tinycloud/web-sdk";
import type { SharePublicConfig } from "../email-share/config.js";

/**
 * Construct the SDK receiver without an OpenKey provider. `identity: auto`
 * may restore a real TinyCloud session, but an OpenKey cookie alone cannot
 * turn this into the account branch.
 */
export async function createShareReceiverClient(
  config: SharePublicConfig,
  registryBaseUrl: string,
): Promise<TinyCloudWeb> {
  const nodeHost = import.meta.env.VITE_SHARE_HERMETIC === "true"
    ? window.location.origin
    : config.nodeOrigin;
  return TinyCloudWeb.create({
    tinycloudHosts: [nodeHost],
    tinycloudFallbackHosts: null,
    tinycloudRegistryUrl: null,
    autoDiscoverLocalNode: false,
    autoCreateSpace: false,
    domain: new URL(config.shareOrigin).hostname,
    sessionStorageKeyPrefix: "tinycloud-share",
    notifications: { popups: false },
    shareReceiver: {
      origin: window.location.origin,
      expectedShareOrigin: config.shareOrigin,
      registryBaseUrl,
      credentialDiscoveryUrl: `${config.credentialsOrigin}/.well-known/opencredentials`,
      // Unified v3 envelopes target the attested Ed25519 enforcer DID. The
      // deployment's did:web nodeAudience remains the public routing identity.
      expectedEnforcerDid: config.enforcerDid,
      trustedNode: {
        invitationKid: config.nodeInvitationKid,
        invitationPublicKey: fromBase64Url(config.nodeInvitationPublicKey),
      },
    },
  });
}
