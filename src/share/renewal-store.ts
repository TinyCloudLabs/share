/**
 * The renewal receipt of the library session on this device: the owner-signed lease OpenKey returned at sign-in,
 * kept beside the session the SDK saved (same prefix). It is trusted for nothing until `renewal-receipt.ts` checks
 * it against the saved session record. No SDK imports, so the page can ask whether a session may still renew
 * before OpenKey or the SDK load.
 */

/** Not an address, so it never meets the SDK's `<prefix><address>` records. */
const receiptKey = (prefix: string): string => `${prefix}renewal-receipt`;

interface StoredReceipt {
  readonly address: string;
  readonly receipt: unknown;
}

/** Keeps `receipt` for `address`. Storage that refuses the write leaves no receipt: the session then ends at its signed end. */
export function saveRenewalReceipt(prefix: string, address: string, receipt: unknown, storage?: Pick<Storage, "setItem">): boolean {
  try {
    (storage ?? window.localStorage).setItem(receiptKey(prefix), JSON.stringify({ address, receipt } satisfies StoredReceipt));
    return true;
  } catch {
    return false;
  }
}

/** The receipt kept for `address`, unverified, or null. */
export function loadRenewalReceipt(prefix: string, address: string, storage?: Pick<Storage, "getItem">): unknown {
  try {
    const stored: unknown = JSON.parse((storage ?? window.localStorage).getItem(receiptKey(prefix)) ?? "null");
    if (typeof stored !== "object" || stored === null || !("address" in stored) || !("receipt" in stored)) return null;
    return typeof stored.address === "string" && stored.address.toLowerCase() === address.toLowerCase() ? stored.receipt ?? null : null;
  } catch {
    return null;
  }
}

/**
 * True when a receipt is kept for `address` whose signed lease end (as the receipt states it, unverified) has not passed.
 * It only decides whether the page tries a lease restore; `renewal-receipt.ts` verifies the receipt and the node decides.
 */
export function renewalReceiptRunning(prefix: string, address: string, storage?: Pick<Storage, "getItem">): boolean {
  const stored = loadRenewalReceipt(prefix, address, storage);
  if (typeof stored !== "object" || stored === null || !("receipt" in stored)) return false;
  const { receipt } = stored;
  if (typeof receipt !== "object" || receipt === null || !("leaseExpiresAt" in receipt) || typeof receipt.leaseExpiresAt !== "string") return false;
  return Date.parse(receipt.leaseExpiresAt) > Date.now();
}

/** Removes the receipt. Never throws. */
export function clearRenewalReceipt(prefix: string, storage?: Pick<Storage, "removeItem">): void {
  try { (storage ?? window.localStorage).removeItem(receiptKey(prefix)); } catch { /* Blocked storage holds nothing to remove. */ }
}

/** What Share asks OpenKey to offer: renewal for up to 90 days, on by default (`standing`). */
export const SIGN_IN_RENEWAL_ASK = { version: 1, leaseLifetimeSeconds: 90 * 24 * 60 * 60, purpose: "standing" } as const;

/** The lease receipt in an `authorizeTinyCloud` result, only when the owner left renewal on (`renewalChoice: "leased"`); otherwise undefined. Unverified. */
export function leaseFromApproval(result: unknown): unknown {
  if (typeof result !== "object" || result === null || !("renewalChoice" in result) || result.renewalChoice !== "leased") return undefined;
  return "renewal" in result ? result.renewal : undefined;
}

/** True when any receipt is kept under `prefix`. A page without one loads none of the renewal code. */
export function hasRenewalReceipt(prefix: string, storage?: Pick<Storage, "getItem">): boolean {
  try { return (storage ?? window.localStorage).getItem(receiptKey(prefix)) !== null; } catch { return false; }
}
