/**
 * Share's library session on this device. The web SDK persists it in localStorage under
 * `LIBRARY_SESSION_PREFIX` (see `persistSession` in openkey-session.ts), so a reload restores it
 * with no new approval while it is still valid. Beside it Share keeps the OpenKey account it belongs
 * to (address, key id, key type: public, no credential), so a reload can rebuild the signer without
 * reconnecting OpenKey. A module of its own so the page can ask, before OpenKey or the SDK load,
 * whether there is a session to resume.
 */
import type { AuthResult } from "@openkey/sdk";

/** The SDK's storage-key prefix for the library session. Its own, so no other Share sign-in reads or replaces it. */
export const LIBRARY_SESSION_PREFIX = "tinycloud-share-library-";
/** Not an address, so it never meets the SDK's `<prefix><address>` records. */
const ACCOUNT_KEY = `${LIBRARY_SESSION_PREFIX}openkey-account`;

/**
 * The OpenKey account of an unexpired library session saved on this device, or undefined. It only decides
 * whether the page resumes: the SDK still decides whether the session is restored, and signs in afresh when it
 * is expired, corrupt or no longer covers the library. Reads the web SDK's BrowserSessionStorage layout: the
 * active address under `<prefix>active-address`, its record under `<prefix><address>` with an ISO `expiresAt`.
 */
export function savedLibraryAccount(storage?: Pick<Storage, "getItem">): AuthResult | undefined {
  try {
    // Inside the try: reading `localStorage` throws where the browser blocks it.
    const store = storage ?? window.localStorage;
    const address = store.getItem(`${LIBRARY_SESSION_PREFIX}active-address`);
    if (address === null) return undefined;
    const record: unknown = JSON.parse(store.getItem(`${LIBRARY_SESSION_PREFIX}${address}`) ?? "null");
    const expiresAt = typeof record === "object" && record !== null && "expiresAt" in record && typeof record.expiresAt === "string" ? Date.parse(record.expiresAt) : Number.NaN;
    if (!(Number.isFinite(expiresAt) && expiresAt > Date.now())) return undefined;
    const account: unknown = JSON.parse(store.getItem(ACCOUNT_KEY) ?? "null");
    if (typeof account !== "object" || account === null || !("address" in account) || !("keyId" in account) || !("keyType" in account)) return undefined;
    const { address: accountAddress, keyId, keyType } = account;
    if (typeof accountAddress !== "string" || accountAddress.toLowerCase() !== address.toLowerCase() || typeof keyId !== "string" || (keyType !== "MANAGED" && keyType !== "EXTERNAL")) return undefined;
    return { address: accountAddress, keyId, keyType };
  } catch {
    // Storage the browser blocks, or a record that is not JSON: nothing to resume.
    return undefined;
  }
}

/** Remembers which OpenKey account the library session belongs to. Storage that refuses the write only costs the next reload its resume. */
export function saveLibraryAccount(auth: AuthResult): void {
  try { window.localStorage.setItem(ACCOUNT_KEY, JSON.stringify({ address: auth.address, keyId: auth.keyId, keyType: auth.keyType })); } catch { /* Not saved: the next load signs in. */ }
}

/** Forgets the account at sign-out, with the session the SDK clears. */
export function forgetLibraryAccount(): void {
  try { window.localStorage.removeItem(ACCOUNT_KEY); } catch { /* Blocked storage holds nothing to forget. */ }
}
