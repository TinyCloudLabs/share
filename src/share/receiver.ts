import { TinyCloudWeb } from "@tinycloud/web-sdk";
import type { SharePublicConfig } from "../email-share/config.js";

/**
 * Construct the SDK receiver without an OpenKey provider. `identity: auto`
 * may restore a real TinyCloud session, but an OpenKey cookie alone cannot
 * turn this into the account branch.
 */
export async function createShareReceiverClient(
  config: SharePublicConfig,
): Promise<TinyCloudWeb> {
  const nodeHost = import.meta.env.VITE_SHARE_HERMETIC === "true"
    ? window.location.origin
    : undefined;
  return TinyCloudWeb.create({
    ...(nodeHost === undefined ? {} : { tinycloudHosts: [nodeHost] }),
    tinycloudFallbackHosts: null,
    tinycloudRegistryUrl: nodeHost === undefined ? config.registryOrigin : null,
    autoDiscoverLocalNode: false,
    autoCreateSpace: false,
    domain: new URL(config.shareOrigin).hostname,
    sessionStorageKeyPrefix: "tinycloud-share",
    notifications: { popups: false },
    shareReceiver: {
      origin: window.location.origin,
      expectedShareOrigin: config.shareOrigin,
      credentialDiscoveryUrl: `${config.credentialsOrigin}/.well-known/opencredentials`,
    },
  });
}
