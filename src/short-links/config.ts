/** The links API this build talks to. It comes from build configuration, never from a link. */
export const DEFAULT_LINKS_API_ORIGIN = "https://api.tinycloud.xyz";

/**
 * `VITE_LINKS_API_ORIGIN` names a self-hosted API. Anything but a canonical https origin is refused;
 * the hermetic test build (`VITE_SHARE_VIEWER_HERMETIC`) may also use a loopback http origin.
 */
export function linksApiOrigin(env: Readonly<Record<string, unknown>> = import.meta.env): string {
  const configured = env["VITE_LINKS_API_ORIGIN"];
  if (configured === undefined || configured === "") return DEFAULT_LINKS_API_ORIGIN;
  if (typeof configured !== "string") throw new TypeError("links API origin must be a string");
  const url = new URL(configured);
  const loopback = env["VITE_SHARE_VIEWER_HERMETIC"] === "true" && url.protocol === "http:" && url.hostname === "127.0.0.1";
  if ((url.protocol !== "https:" && !loopback) || url.origin !== configured) throw new TypeError("links API origin must be a canonical https origin");
  return configured;
}
