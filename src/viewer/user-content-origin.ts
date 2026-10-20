/**
 * The ONE place that says where sandbox documents and runtime assets live.
 *
 * `VITE_USER_CONTENT_ORIGIN` (build time) is empty by default: frames and
 * library files are then same-origin relative paths, which is how Share ships
 * today. Set to an origin such as `https://usercontent.tinycloud.xyz`, every
 * sandbox frame URL (`/jsx-sandbox.html#<nonce>`, `/artifact-sandbox.html`,
 * `/mermaid-sandbox.html`) and every runtime file URL
 * (`/assets/jsx-runtime/<name>.<hash>.js`) is built from it, and the viewer's
 * own CSP names exactly that origin in `frame-src` and `connect-src`
 * (vite.config.ts, src/artifact/user-content/headers.ts). The sandbox
 * controllers (artifact-/jsx-/mermaid-sandbox.ts) and the module loader
 * (jsx-modules.ts) build URLs only through `userContentUrl`; a test greps for
 * hard-coded paths elsewhere.
 *
 * Moving to another origin changes where bytes come from, not who is trusted:
 * the frames are sandboxed WITHOUT allow-same-origin, so their origin is the
 * string "null" whatever host served them, and library texts are accepted only
 * when their sha256 equals the manifest embedded in the viewer build.
 */

/**
 * Returns "" (same origin) or a bare origin. Only `https:` is accepted, plus
 * `http:` for a loopback host so a local usercontent server can be tested.
 * Anything else (a path, credentials, a query, another scheme) throws, so a
 * misconfigured build fails instead of shipping frames from a surprise host.
 */
export function parseUserContentOrigin(raw: string | undefined): string {
  const value = (raw ?? "").trim();
  if (value === "") return "";
  let url: URL;
  try { url = new URL(value); } catch { throw new Error(`VITE_USER_CONTENT_ORIGIN is not a URL: ${value}`); }
  const loopback = url.hostname === "127.0.0.1" || url.hostname === "localhost" || url.hostname === "[::1]";
  if (url.protocol !== "https:" && !(url.protocol === "http:" && loopback)) {
    throw new Error("VITE_USER_CONTENT_ORIGIN must be an https origin");
  }
  if (url.username !== "" || url.password !== "" || url.search !== "" || url.hash !== "" || (url.pathname !== "/" && url.pathname !== "")) {
    throw new Error("VITE_USER_CONTENT_ORIGIN must be an origin only: no credentials, path, query or fragment");
  }
  return url.origin;
}

export const USER_CONTENT_ORIGIN: string = parseUserContentOrigin(
  // `env` exists in Vite and vitest; the optional chain lets Node build scripts import this module.
  import.meta.env?.["VITE_USER_CONTENT_ORIGIN"],
);

/** `path` must start with "/"; it may carry a `#fragment`. */
export function userContentUrl(path: string, origin: string = USER_CONTENT_ORIGIN): string {
  if (!path.startsWith("/") || path.startsWith("//")) throw new Error("user content path must be absolute-path");
  return `${origin}${path}`;
}
