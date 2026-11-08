/**
 * Share's library session on this device. The web SDK persists it in localStorage under
 * `LIBRARY_SESSION_PREFIX` (see `persistSession` in openkey-session.ts), so a reload restores it
 * with no new approval while it is still valid. A module of its own so the sign-in wall can ask,
 * before OpenKey or the SDK load, whether there is one to resume.
 */

/** The SDK's storage-key prefix for the library session. Its own, so no other Share sign-in reads or replaces it. */
export const LIBRARY_SESSION_PREFIX = "tinycloud-share-library-";

/**
 * True when this device holds an unexpired library session record. It only chooses the sign-in wall's words
 * ("Welcome back"): the SDK still decides whether the session is restored, and signs in afresh when it is
 * expired, corrupt, for another account or no longer covers the library. Reads the web SDK's
 * BrowserSessionStorage layout: the active address under `<prefix>active-address`, its record under
 * `<prefix><address>` with an ISO `expiresAt`.
 */
export function hasSavedLibrarySession(storage?: Pick<Storage, "getItem">): boolean {
  try {
    // Inside the try: reading `localStorage` throws where the browser blocks it.
    const store = storage ?? window.localStorage;
    const address = store.getItem(`${LIBRARY_SESSION_PREFIX}active-address`);
    if (address === null) return false;
    const record: unknown = JSON.parse(store.getItem(`${LIBRARY_SESSION_PREFIX}${address}`) ?? "null");
    const expiresAt = typeof record === "object" && record !== null && "expiresAt" in record && typeof record.expiresAt === "string" ? Date.parse(record.expiresAt) : Number.NaN;
    return Number.isFinite(expiresAt) && expiresAt > Date.now();
  } catch {
    // Storage the browser blocks, or a record that is not JSON: nothing to resume.
    return false;
  }
}
