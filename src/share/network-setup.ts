import { defaultEncryptionNetworkForOwner } from "@tinycloud/share-sdk";
import type { OpenKeyShareSession, ShareTinyCloud } from "./openkey-session.js";
import { NETWORK_SETUP } from "./history-copy.js";
import { NetworkSetupDeclinedError } from "./network-setup-declined.js";
import { requestInOpenKey } from "./permission-step-up.js";

export interface NetworkSetup {
  /** Resolves once the account's encryption network exists. Asks nothing when it already does; once per session. */
  ensure(): Promise<void>;
}

/** The one-time setup needs its approval for the moment only: ten minutes, not the SDK's 30-day default. */
const NETWORK_SETUP_GRANT_MS = 600_000;

type SetupClient = Pick<ShareTinyCloud, "getEncryptionNetwork" | "ensureEncryptionNetwork" | "requestPermissions" | "hasPermissions">;

export function createNetworkSetup(tinycloud: SetupClient, session: Pick<OpenKeyShareSession, "address">, onStatus: (message: string) => void = () => undefined): NetworkSetup {
  let ready = false;
  let running: Promise<void> | undefined;
  const run = async (): Promise<void> => {
    const networkId = defaultEncryptionNetworkForOwner({ address: session.address });
    if (await tinycloud.getEncryptionNetwork(networkId) === null) {
      onStatus(NETWORK_SETUP);
      const approved = await requestInOpenKey(tinycloud, [{ service: "tinycloud.encryption", path: networkId, actions: ["network.create"], skipPrefix: true }], { expiryMs: NETWORK_SETUP_GRANT_MS });
      if (!approved) throw new NetworkSetupDeclinedError();
      // The same id the grant names.
      await tinycloud.ensureEncryptionNetwork(networkId);
    }
    ready = true;
  };
  return {
    ensure: () => {
      if (ready) return Promise.resolve();
      running ??= run().finally(() => { running = undefined; });
      return running;
    },
  };
}
