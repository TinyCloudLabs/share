/** Where earlier builds kept the receiver's exportable key; it is only ever removed. */
export const LEGACY_RECEIVER_SESSION_KEY = "tinycloud.share.receiver-session.v1";
/** Receiver credentials; those issued to a legacy key go with it. */
export const RECEIVER_CREDENTIALS_KEY = "tinycloud.share.receiver-credentials.v1";

/**
 * Removes a receiver key record an earlier build left in this tab, with the
 * credentials issued to it. Credentials for the current non-extractable key
 * stay. The storage getter itself throws where site storage is blocked, so it
 * is read inside the guard; the page then simply has nothing to purge.
 */
export function purgeLegacyReceiverStorage(storage: () => Pick<Storage, "getItem" | "removeItem"> = () => window.sessionStorage): void {
  try {
    const target = storage();
    if (target.getItem(LEGACY_RECEIVER_SESSION_KEY) === null) return;
    target.removeItem(LEGACY_RECEIVER_SESSION_KEY);
    target.removeItem(RECEIVER_CREDENTIALS_KEY);
  } catch { /* storage is blocked, so it holds no receiver records */ }
}
