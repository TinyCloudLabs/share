import { defaultEncryptionNetworkForOwner } from "@tinycloud/share-sdk";
import type { OpenKeyShareSession, ShareTinyCloud } from "./openkey-session.js";
import { NETWORK_SETUP } from "./history-copy.js";
import { requestInOpenKey } from "./permission-step-up.js";

/** The person did not approve the one-time setup. Reads as a sign-in that did not complete. */
export class NetworkSetupDeclinedError extends Error {
  readonly kind = "signIn" as const;
  constructor() { super("network-setup-declined"); }
}

export interface NetworkSetup {
  /** Resolves once the account's encryption network exists. Asks nothing when it already does; once per session. */
  ensure(): Promise<void>;
}

type SetupClient = Pick<ShareTinyCloud, "getEncryptionNetwork" | "ensureEncryptionNetwork" | "requestPermissions">;

export function createNetworkSetup(tinycloud: SetupClient, session: Pick<OpenKeyShareSession, "address">, onStatus: (message: string) => void = () => undefined): NetworkSetup {
  let ready = false;
  let running: Promise<void> | undefined;
  const run = async (): Promise<void> => {
    const networkId = defaultEncryptionNetworkForOwner({ address: session.address });
    if (await tinycloud.getEncryptionNetwork(networkId) === null) {
      onStatus(NETWORK_SETUP);
      const approved = await requestInOpenKey(tinycloud, [{ service: "tinycloud.encryption", path: networkId, actions: ["network.create"], skipPrefix: true }]);
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
