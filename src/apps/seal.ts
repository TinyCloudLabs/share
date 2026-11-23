import { extractRecapAttenuations, pkhDid, verifyEip191MessageSignature, type ClientSession } from "@tinycloud/sdk-core";
import type { NamedKeyClient, NamedKeyEnvelope } from "@tinycloud/node-sdk/encryption-keys";

import { SEAL_ABILITIES } from "./seal-key.ts";

export interface BoundSeal {
  readonly keyPath: string;
  readonly networkId: string;
  readonly ownerDid: string;
  readonly spaceId: string;
  encrypt(bytes: Uint8Array, aad: Uint8Array): Promise<NamedKeyEnvelope>;
  decrypt(envelope: NamedKeyEnvelope): Promise<Uint8Array>;
}

/** Bind the named-key client only to an exact owner-direct grant on the active session. */
export async function bindSeal(
  keyPath: string,
  spaceId: string,
  session: ClientSession | undefined,
  keys: () => Pick<NamedKeyClient, "ensureKey" | "encrypt" | "decrypt">,
): Promise<BoundSeal | undefined> {
  if (session === undefined) return undefined;
  let ownerDid: string;
  let networkId: string;
  try {
    ownerDid = pkhDid(session.address, session.chainId);
    networkId = `urn:tinycloud:encryption:${ownerDid}:default`;
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
    ownerDid,
    spaceId,
    async encrypt(bytes, aad) {
      const client = keys();
      ready ??= client.ensureKey(keyPath, { networkId }).catch((error: unknown) => {
        ready = undefined;
        throw error;
      });
      await ready;
      return client.encrypt(keyPath, bytes, { networkId, keyWrapV2: true, aad });
    },
    decrypt: (envelope) => keys().decrypt(envelope),
  };
}
