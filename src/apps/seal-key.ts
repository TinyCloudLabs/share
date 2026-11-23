/** The browser origin must own this named-key namespace in OpenKey and on the node. */
export const RUNNER_KEY_NAMESPACE = "xyz.tinycloud.share";
export const SEAL_ABILITIES = ["decrypt", "key.create"] as const;

/** Returns the app's own exact key, undefined for no request or null for an invalid request. */
export function runnerSealingKey(manifest: unknown): string | null | undefined {
  if (typeof manifest !== "object" || manifest === null) return null;
  const { app_id: appId, keys_app_id: namespace, keys, permissions } = manifest as Record<string, unknown>;
  // Direct encryption rows are never part of the runner contract. App key grants
  // are signed by the SDK through manifest.keys and do not appear in resolveManifest.
  if (Array.isArray(permissions) && permissions.some((row) =>
    typeof row?.service === "string" && /^(?:tinycloud\.)?encryption$/i.test(row.service),
  )) return null;
  if (keys === undefined && namespace === undefined) return undefined;
  if (namespace !== RUNNER_KEY_NAMESPACE || typeof appId !== "string" ||
      !/^[a-z0-9][a-z0-9._-]{0,63}$/.test(appId) || appId.endsWith("\n") ||
      !Array.isArray(keys) || keys.length !== 1) return null;
  const declaration: unknown = keys[0];
  if (typeof declaration !== "object" || declaration === null || Array.isArray(declaration) ||
      Object.keys(declaration).length !== 2) return null;
  const { path, abilities } = declaration as Record<string, unknown>;
  const expected = `apps/${RUNNER_KEY_NAMESPACE}/${appId}/seal-v1`;
  return path === expected && Array.isArray(abilities) && abilities.length === SEAL_ABILITIES.length &&
    SEAL_ABILITIES.every((ability) => abilities.includes(ability)) ? expected : null;
}
