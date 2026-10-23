export interface CapturedLaunch {
  shareHref: string;
  /** `bearer`: a native `#tc1` capability. `link`: a `/s/…` or `/c/…` link that the link reader checks. */
  readonly kind: "bearer" | "link";
}

const NATIVE_LAUNCH = /^#tc1=([^&]+)$/;
const LINK_PATH = /^\/(?:s|c)\/[A-Za-z0-9]+$/;
/** The largest fragment the reader is given: a full link carries a 128 KiB sealed body, base64url twice over. */
const MAX_LINK_FRAGMENT = 700_000;

/**
 * Capture the launch link, then remove its material from browser history before configuration
 * loading or network work:
 *
 * - `#tc1` is a secret bearer capability.
 * - `/s/<id>`, `/c/<id>` and `/s/full` with a `#v=…` fragment are links for the link reader, which
 *   accepts the `v=4` grammar and refuses everything else.
 *
 * No plaintext `?tc2`, unresolved compact `/s/<cid>`, claim-secret, or reload-cache form is accepted.
 */
export function captureAndScrubLaunch(loc: Location, history: History): CapturedLaunch | undefined {
  const href = loc.href;
  const pathname = loc.pathname;
  const search = loc.search;
  const hash = loc.hash;
  history.replaceState(null, "", "/viewer");
  if (pathname === "/viewer" && search === "") {
    return NATIVE_LAUNCH.test(hash) ? { shareHref: href, kind: "bearer" } : undefined;
  }
  if (!LINK_PATH.test(pathname) && pathname !== "/s/full") return undefined;
  // A fragment past the bound is passed on without it, so the reader refuses it without holding it.
  return { shareHref: hash.length > MAX_LINK_FRAGMENT ? `${loc.origin}${pathname}` : href, kind: "link" };
}
