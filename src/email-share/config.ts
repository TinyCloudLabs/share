const CONFIG_VERSION = "tinycloud.share/config-v2" as const;

/** Public routing only. Owner Node identity comes from registry discovery and signed share material. */
export interface SharePublicConfig {
  readonly version: typeof CONFIG_VERSION;
  readonly shareOrigin: string;
  readonly registryOrigin: string;
  readonly credentialsOrigin: string;
  readonly emailOrigin: string;
  readonly accountlessReceiverEnabled: boolean;
  readonly environment?: "production" | "test";
}

function exactObject(value: unknown, keys: readonly string[]): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new TypeError("share config must be an object");
  const object = value as Record<string, unknown>;
  if (Object.keys(object).length !== keys.length || keys.some((key) => !Object.hasOwn(object, key))) throw new TypeError("share config has unknown or missing fields");
  return object;
}

function httpsOrigin(value: unknown, name: string): string {
  if (typeof value !== "string") throw new TypeError(`${name} is missing`);
  const parsed = new URL(value);
  if (parsed.protocol !== "https:" || parsed.origin !== value) throw new TypeError(`${name} must be a canonical HTTPS origin`);
  return value;
}

export function validateSharePublicConfig(value: unknown): SharePublicConfig {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new TypeError("share config must be an object");
  const raw = value as Record<string, unknown>;
  const object = exactObject(value, ["version", "shareOrigin", "registryOrigin", "credentialsOrigin", "emailOrigin", "accountlessReceiverEnabled", ...(Object.hasOwn(raw, "environment") ? ["environment"] : [])]);
  if (object.version !== CONFIG_VERSION) throw new TypeError("unsupported share config version");
  const shareOrigin = httpsOrigin(object.shareOrigin, "shareOrigin");
  const registryOrigin = httpsOrigin(object.registryOrigin, "registryOrigin");
  const credentialsOrigin = httpsOrigin(object.credentialsOrigin, "credentialsOrigin");
  const emailOrigin = httpsOrigin(object.emailOrigin, "emailOrigin");
  const environment = object.environment === undefined ? "production" : object.environment;
  if (environment !== "production" && environment !== "test") throw new TypeError("share config environment is invalid");
  if (typeof object.accountlessReceiverEnabled !== "boolean") throw new TypeError("share receiver rollout is invalid");
  if (environment === "production" && [shareOrigin, registryOrigin, credentialsOrigin, emailOrigin].some((item) => /(?:node\.example|127\.0\.0\.1|localhost|fixture|test)/i.test(item))) throw new TypeError("production share config contains a placeholder or loopback value");
  return Object.freeze({
    version: CONFIG_VERSION,
    shareOrigin,
    registryOrigin,
    credentialsOrigin,
    emailOrigin,
    accountlessReceiverEnabled: object.accountlessReceiverEnabled,
    ...(environment === "test" ? { environment: "test" as const } : {}),
  });
}

export async function loadSharePublicConfig(fetchFn: typeof fetch = globalThis.fetch.bind(globalThis), url = "/.well-known/tinycloud-share/config.json"): Promise<SharePublicConfig> {
  const parsed = new URL(url, globalThis.location?.origin ?? "https://share.tinycloud.xyz");
  if (parsed.origin !== (globalThis.location?.origin ?? parsed.origin)) throw new TypeError("share config must be same-origin");
  const response = await fetchFn(parsed, { credentials: "omit", cache: "no-store", redirect: "error", referrerPolicy: "no-referrer" });
  if (!response.ok) throw new Error(`share config unavailable (${response.status})`);
  const rollout = response.headers.get("x-tinycloud-share-accountless-receiver");
  if (rollout !== null && rollout !== "enabled" && rollout !== "disabled") throw new TypeError("share receiver rollout is invalid");
  const config = validateSharePublicConfig(await response.json());
  return Object.freeze({
    ...config,
    accountlessReceiverEnabled: rollout === null ? config.accountlessReceiverEnabled : rollout === "enabled",
  });
}
