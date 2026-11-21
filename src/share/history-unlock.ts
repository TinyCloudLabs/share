import type { PermissionEntry } from "@tinycloud/web-sdk";
import { defaultEncryptionNetworkForOwner } from "@tinycloud/share-sdk";
import { ownerEncryptionNetwork, type OpenKeyShareSession, type ShareTinyCloud } from "./openkey-session.js";
import { requestInOpenKeyUntil, type StepUpResult } from "./permission-step-up.js";

/** How long "Unlock" keeps the sent-shares list readable: the requested lifetime of the grant. */
export const HISTORY_UNLOCK_MS = 3_600_000;

/** Decrypt on the owner's encryption network: what reading the saved sent shares needs. */
export function decryptNetworkPermission(address: string): PermissionEntry {
  return { service: "tinycloud.encryption", path: defaultEncryptionNetworkForOwner({ address }), actions: ["decrypt"], skipPrefix: true };
}

/**
 * Makes the sent-shares list readable: nothing to ask while the grant is live, otherwise one OpenKey approval for
 * `HISTORY_UNLOCK_MS`. `approved` is true when it is readable now and false when the person did not approve (the list
 * stays locked); `expiresAt` is when the new grant ends, when the SDK said.
 */
export async function unlockHistory(tinycloud: Pick<ShareTinyCloud, "hasPermissions" | "requestPermissions">, session: Pick<OpenKeyShareSession, "address">): Promise<StepUpResult> {
  const needed = [decryptNetworkPermission(session.address)];
  if (tinycloud.hasPermissions(needed)) return { approved: true };
  return requestInOpenKeyUntil(tinycloud, needed, { expiryMs: HISTORY_UNLOCK_MS });
}

/** What the library asks to know whether the list is readable, and the one way to make it so. */
export interface HistoryLock {
  isUnlocked(): boolean;
  unlock(): Promise<boolean>;
  /** Epoch ms the grant from `unlock` ends, or undefined when this page has not asked for one. */
  lapsesAt(): number | undefined;
}

export function historyLock(tinycloud: Pick<ShareTinyCloud, "hasPermissions" | "requestPermissions">, session: Pick<OpenKeyShareSession, "address">): HistoryLock {
  let lapses: number | undefined;
  return {
    isUnlocked: () => tinycloud.hasPermissions([decryptNetworkPermission(session.address)]),
    unlock: async () => {
      const held = tinycloud.hasPermissions([decryptNetworkPermission(session.address)]);
      const { approved, expiresAt } = await unlockHistory(tinycloud, session);
      // The end the SDK gave the grant (it can be earlier than the hour asked for, when the session ends first); without one, the requested hour from now.
      if (approved && !held) lapses = expiresAt ?? Date.now() + HISTORY_UNLOCK_MS;
      return approved;
    },
    lapsesAt: () => lapses,
  };
}

/**
 * True when a saved session still holds what Share's sign-in used to ask for: decrypt on the whole encryption network,
 * or the right to create it. Either spelling of the network id counts. Decrypt under `share/` is not that.
 */
export function holdsWholeNetworkAccess(tinycloud: Pick<ShareTinyCloud, "hasPermissions">, address: string): boolean {
  return [...new Set([ownerEncryptionNetwork(address), defaultEncryptionNetworkForOwner({ address })])].some((path) =>
    (["decrypt", "network.create"] as const).some((action) => tinycloud.hasPermissions([{ service: "tinycloud.encryption", path, actions: [action], skipPrefix: true }])));
}
