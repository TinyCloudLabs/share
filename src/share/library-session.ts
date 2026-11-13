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
const SIGN_OUT_GENERATION_KEY = `${LIBRARY_SESSION_PREFIX}sign-out-generation`;
let signOutGeneration = 0;

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
    return libraryAccountForAddress(store, address);
  } catch {
    return undefined;
  }
}

function libraryAccountForAddress(store: Pick<Storage, "getItem">, address: string): AuthResult | undefined {
  try {
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
  signOutGeneration += 1;
  try {
    window.localStorage.setItem(SIGN_OUT_GENERATION_KEY, crypto.randomUUID());
  } catch { /* This tab still advances its generation when storage refuses the write. Details: TC-2872 */ }
  try { window.localStorage.removeItem(ACCOUNT_KEY); } catch { /* Blocked storage holds nothing to forget. */ }
}

/**
 * Whether OpenKey holds a sign-in in this tab. OpenKey's embedded window keeps its sign-in per tab, and since a
 * saved session resumes without opening OpenKey, a resumed tab often holds none. Share marks the tab when OpenKey
 * connects or signs in it (both need OpenKey's sign-in there) and asks OpenKey to sign out only when marked.
 * sessionStorage, like OpenKey's own: a reload keeps it, a new tab starts without it.
 */
const OPENKEY_TAB_KEY = "tinycloud-share-openkey-signed-in";

export function markOpenKeySignedInHere(): void {
  try { window.sessionStorage.setItem(OPENKEY_TAB_KEY, "1"); } catch { /* Unmarked: sign-out then leaves OpenKey alone and says so. */ }
}

export function openKeySignedInHere(): boolean {
  try { return window.sessionStorage.getItem(OPENKEY_TAB_KEY) === "1"; } catch { return false; }
}

export function forgetOpenKeySignedInHere(): void {
  try { window.sessionStorage.removeItem(OPENKEY_TAB_KEY); } catch { /* Nothing stored. */ }
}

/** Discovers a library restore candidate for an explicitly approved lease. Details: TC-2872 */
export async function savedLibraryRenewalAccount(leaseAuthorization: string, storage?: Storage): Promise<AuthResult | undefined> {
  try {
    return (await libraryRenewalCandidate(leaseAuthorization, storage)).account;
  } catch {
    return undefined;
  }
}

/** Keeps a library reload attached to the selected account and sign-out generation. Details: TC-2872 */
export async function libraryRenewalCandidate(leaseAuthorization: string, storage?: Storage, expectedAccount?: AuthResult): Promise<{ account: AuthResult; assertCurrent(): void }> {
  if (!leaseAuthorization) throw new Error("library-renewal-candidate");
  const store = storage ?? window.localStorage;
  const address = store.getItem(`${LIBRARY_SESSION_PREFIX}active-address`);
  const account = address === null ? undefined : libraryAccountForAddress(store, address);
  if (address === null || account === undefined || (expectedAccount !== undefined &&
      (account.address.toLowerCase() !== expectedAccount.address.toLowerCase() || account.keyId !== expectedAccount.keyId || account.keyType !== expectedAccount.keyType))) throw new Error("library-renewal-account");
  const signature = (): unknown => {
    const record: unknown = JSON.parse(store.getItem(`${LIBRARY_SESSION_PREFIX}${address.toLowerCase()}`) ?? "null");
    return typeof record === "object" && record !== null && "signature" in record ? record.signature : undefined;
  };
  const originalSignature = signature();
  if (typeof originalSignature !== "string") throw new Error("library-renewal-candidate");
  const generation = signOutGeneration;
  const savedGeneration = store.getItem(SIGN_OUT_GENERATION_KEY);
  const { BrowserSessionStorage } = await import("@tinycloud/web-sdk");
  const sessions = new BrowserSessionStorage({ storage: store, keyPrefix: LIBRARY_SESSION_PREFIX });
  const assertCurrent = (): void => {
    if (sessions.isSignedOut(address, originalSignature)) throw new Error("library-renewal-signed-out");
    const current = libraryAccountForAddress(store, address);
    if (signOutGeneration !== generation || store.getItem(SIGN_OUT_GENERATION_KEY) !== savedGeneration ||
        store.getItem(`${LIBRARY_SESSION_PREFIX}active-address`)?.toLowerCase() !== address.toLowerCase() ||
        current?.address.toLowerCase() !== account.address.toLowerCase() || current?.keyId !== account.keyId || current?.keyType !== account.keyType ||
        signature() !== originalSignature) throw new Error("library-renewal-state-changed");
  };
  assertCurrent();
  const candidate = await sessions.loadRenewalCandidate(address);
  assertCurrent();
  if (candidate.status !== "loaded" && candidate.status !== "renewal-candidate") throw new Error("library-renewal-candidate");
  return { account, assertCurrent };
}
