/**
 * Share no longer hosts apps. The app runner kept each app's sign-in in this browser's localStorage, under
 * `tinycloud-share-runner-<hash>` (the SDK's session record, the renewal receipt, the kept grants), so a visitor who
 * had opened an app still holds a sign-in nothing on Share can use or end. Every page forgets them on the next visit.
 * This clears the browser's own records only: no space is read or written, and nothing is revoked at the node or at
 * OpenKey. Delete this once every lease the runner could have asked for (90 days) has expired.
 */
export const RETIRED_APP_SIGN_IN_PREFIX = "tinycloud-share-runner-";

/**
 * Removes every localStorage key under the retired runner prefix, and nothing else. The storage getter itself throws
 * where site storage is blocked, so it is read inside the guard; the page then has nothing to clear.
 */
export function clearRetiredAppSignIns(storage: () => Pick<Storage, "key" | "length" | "removeItem"> = () => window.localStorage): void {
  try {
    const target = storage();
    const retired: string[] = [];
    for (let index = 0; index < target.length; index += 1) {
      const key = target.key(index);
      if (key !== null && key.startsWith(RETIRED_APP_SIGN_IN_PREFIX)) retired.push(key);
    }
    for (const key of retired) target.removeItem(key);
  } catch { /* storage is blocked, so it holds no sign-ins */ }
}
