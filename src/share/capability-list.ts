import type { UploadCapability } from "./openkey-session.js";

export function parseCapabilityList(value: unknown): readonly unknown[] {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new TypeError("Sharing isn't available right now. Try again later.");
  const record = value as Record<string, unknown>;
  if (Object.keys(record).length !== 1 || !Array.isArray(record.capabilities)) throw new TypeError("Sharing isn't available right now. Try again later.");
  return record.capabilities;
}

export async function loadAuthenticatedCapabilities(fetcher: typeof fetch = fetch): Promise<readonly UploadCapability[]> {
  const response = await fetcher("/api/share/capabilities", { credentials: "include", cache: "no-store", redirect: "error", referrerPolicy: "no-referrer" });
  if (response.status === 503) return [];
  if (!response.ok) throw new Error("Sharing isn't available right now. Try again later.");
  return parseCapabilityList(await response.json()) as readonly UploadCapability[];
}
