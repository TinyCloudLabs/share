import type { PermissionEntry } from "@tinycloud/web-sdk";
import { defaultEncryptionNetworkForOwner } from "@tinycloud/share-sdk";
import type { OpenKeyShareSession, ShareTinyCloud } from "./openkey-session.js";
import { requestInOpenKey } from "./permission-step-up.js";

/** How long "Unlock" keeps the sent-shares list readable: the requested lifetime of the grant. */
export const HISTORY_UNLOCK_MS = 3_600_000;

/** Decrypt on the owner's encryption network: what reading the saved sent shares needs. */
export function decryptNetworkPermission(address: string): PermissionEntry {
  return { service: "tinycloud.encryption", path: defaultEncryptionNetworkForOwner({ address }), actions: ["decrypt"], skipPrefix: true };
}

/**
 * Makes the sent-shares list readable: nothing to ask while the grant is live, otherwise one OpenKey approval for
 * `HISTORY_UNLOCK_MS`. True when it is readable now; false when the person did not approve (the list stays locked).
 */
export async function unlockHistory(tinycloud: Pick<ShareTinyCloud, "hasPermissions" | "requestPermissions">, session: Pick<OpenKeyShareSession, "address">): Promise<boolean> {
  const needed = [decryptNetworkPermission(session.address)];
  if (tinycloud.hasPermissions(needed)) return true;
  return requestInOpenKey(tinycloud, needed, { expiryMs: HISTORY_UNLOCK_MS });
}

/** What the library asks to know whether the list is readable, and the one way to make it so. */
export interface HistoryLock {
  isUnlocked(): boolean;
  unlock(): Promise<boolean>;
}

export function historyLock(tinycloud: Pick<ShareTinyCloud, "hasPermissions" | "requestPermissions">, session: Pick<OpenKeyShareSession, "address">): HistoryLock {
  return {
    isUnlocked: () => tinycloud.hasPermissions([decryptNetworkPermission(session.address)]),
    unlock: () => unlockHistory(tinycloud, session),
  };
}
