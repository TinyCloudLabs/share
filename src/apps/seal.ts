import { extractRecapAttenuations, pkhDid, verifyEip191MessageSignature, type ClientSession } from "@tinycloud/sdk-core";
import type { NamedKeyClient, NamedKeyEnvelope } from "@tinycloud/node-sdk/encryption-keys";

import { SEAL_ABILITIES } from "./seal-key.ts";

export interface BoundSeal {
  readonly keyPath: string;
  readonly networkId: string;
  encrypt(bytes: Uint8Array): Promise<NamedKeyEnvelope>;
  decrypt(envelope: NamedKeyEnvelope): Promise<Uint8Array>;
}

/** Bind the named-key client only to an exact owner-direct grant on the active session. */
export async function bindSeal(
  keyPath: string,
  session: ClientSession | undefined,
  keys: () => Pick<NamedKeyClient, "ensureKey" | "encrypt" | "decrypt">,
): Promise<BoundSeal | undefined> {
  if (session === undefined) return undefined;
  let networkId: string;
  try {
    networkId = `urn:tinycloud:encryption:${pkhDid(session.address, session.chainId)}:default`;
    const recap = extractRecapAttenuations(session.siwe);
    const exact = recap[`${networkId}/${keyPath}`];
    const unrestricted = (ability: string) => exact?.[`tinycloud.encryption/${ability}`]?.some((caveat) =>
      typeof caveat === "object" && caveat !== null && !Array.isArray(caveat) && Object.keys(caveat).length === 0,
    );
    if (!SEAL_ABILITIES.every(unrestricted) ||
        !await verifyEip191MessageSignature(session.siwe, session.signature, session.address)) return undefined;
  } catch {
    return undefined;
  }
  let ready: Promise<unknown> | undefined;
  return {
    keyPath,
    networkId,
    async encrypt(bytes) {
      const client = keys();
      ready ??= client.ensureKey(keyPath, { networkId }).catch((error: unknown) => {
        ready = undefined;
        throw error;
      });
      await ready;
      return client.encrypt(keyPath, bytes, { networkId, keyWrapV2: true });
    },
    decrypt: (envelope) => keys().decrypt(envelope),
  };
}
