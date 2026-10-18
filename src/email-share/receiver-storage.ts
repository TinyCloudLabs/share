/** Receiver key and credential records that earlier builds kept in session storage. */
export const LEGACY_RECEIVER_STORAGE_KEYS = Object.freeze([
  "tinycloud.share.receiver-session.v1",
  "tinycloud.share.receiver-credentials.v1",
]);

/** Removes receiver records left in session storage by earlier builds. */
export function purgeLegacyReceiverStorage(storage: Pick<Storage, "removeItem">): void {
  try {
    for (const key of LEGACY_RECEIVER_STORAGE_KEYS) storage.removeItem(key);
  } catch { /* storage is disabled, so it holds no receiver records */ }
}

export interface PageMemoryStorage {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
}

/**
 * Storage for the receiver's key and credential records that lives only in
 * this page: nothing is written to session storage, and a reload asks the
 * recipient to verify their email again.
 */
export function pageMemoryStorage(): PageMemoryStorage {
  const values = new Map<string, string>();
  return {
    getItem: (key) => values.get(key) ?? null,
    setItem: (key, value) => { values.set(key, value); },
    removeItem: (key) => { values.delete(key); },
  };
}
