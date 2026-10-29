import type { PortableDelegation } from "@tinycloud/web-sdk";

interface RuntimeGrantClient {
  address(): string | undefined;
  useRuntimeDelegation(delegation: PortableDelegation): Promise<void>;
}

interface StoredRuntimeGrantSet {
  readonly version: 1;
  readonly appId: string;
  readonly digest: string;
  readonly ownerAddress: string;
  readonly delegations: readonly string[];
}

function parseStoredRuntimeGrantSet(value: unknown): StoredRuntimeGrantSet | undefined {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return undefined;
  if (!("version" in value) || value.version !== 1 || !("appId" in value) || typeof value.appId !== "string" || !("digest" in value) || typeof value.digest !== "string" || !("ownerAddress" in value) || typeof value.ownerAddress !== "string" || !("delegations" in value) || !Array.isArray(value.delegations)) return undefined;
  const delegations: string[] = [];
  for (const delegation of value.delegations) {
    if (typeof delegation !== "string") return undefined;
    delegations.push(delegation);
  }
  return { version: 1, appId: value.appId, digest: value.digest, ownerAddress: value.ownerAddress, delegations };
}

function removeStoredRuntimeGrants(storage: Storage, key: string): void {
  try {
    storage.removeItem(key);
  } catch {
    // A storage failure cannot widen the current session's permissions.
  }
}

function appStorage(): Storage | undefined {
  try {
    return globalThis.localStorage;
  } catch {
    return undefined;
  }
}

/** Restore only the app/version/owner-scoped delegations, which the SDK validates against its current session key. */
export async function restoreRuntimeGrants(client: RuntimeGrantClient, key: string, appId: string, digest: string): Promise<void> {
  const storage = appStorage();
  const address = client.address();
  if (storage === undefined || address === undefined) return;

  let raw: string | null;
  try {
    raw = storage.getItem(key);
  } catch {
    return;
  }
  if (raw === null) return;

  let value: unknown;
  try {
    value = JSON.parse(raw) as unknown;
  } catch {
    removeStoredRuntimeGrants(storage, key);
    return;
  }
  const stored = parseStoredRuntimeGrantSet(value);
  if (stored === undefined || stored.appId !== appId || stored.digest !== digest || stored.ownerAddress.toLowerCase() !== address.toLowerCase()) {
    removeStoredRuntimeGrants(storage, key);
    return;
  }

  try {
    const { deserializeDelegation } = await import("@tinycloud/web-sdk");
    for (const serialized of stored.delegations) {
      await client.useRuntimeDelegation(deserializeDelegation(serialized));
    }
  } catch {
    removeStoredRuntimeGrants(storage, key);
  }
}

/** Keep only the current installed version's signed runtime grants; the SDK validates them on every restore. */
export async function saveRuntimeGrants(key: string, appId: string, digest: string, ownerAddress: string, delegations: readonly PortableDelegation[]): Promise<void> {
  const storage = appStorage();
  if (storage === undefined) return;
  try {
    if (delegations.length === 0) {
      storage.removeItem(key);
      return;
    }
    const { serializeDelegation } = await import("@tinycloud/web-sdk");
    const record: StoredRuntimeGrantSet = {
      version: 1,
      appId,
      digest,
      ownerAddress,
      delegations: delegations.map(serializeDelegation),
    };
    storage.setItem(key, JSON.stringify(record));
  } catch {
    // The in-memory grant remains active; an unavailable local store only means it cannot survive a reload.
  }
}
