export interface CapturedLaunch {
  shareHref: string;
}

const NATIVE_LAUNCH = /^#tc1=([^&]+)$/;
const PUBLIC_POLICY_QUERY = /^\?tc2=([A-Za-z0-9_-]+)$/;
const MAX_POLICY_QUERY = 700_000;

/**
 * Capture the two cutover link forms, then remove their material from browser
 * history before configuration loading or network work:
 *
 * - `#tc1` is a secret bearer capability.
 * - `?tc2` is a public signed addressed-policy envelope.
 *
 * No pre-cutover `/s/*`, claim-secret, or reload-cache form is accepted.
 */
export function captureAndScrubLaunch(loc: Location, history: History, _storage?: Storage): CapturedLaunch | undefined {
  const href = loc.href;
  const pathname = loc.pathname;
  const search = loc.search;
  const hash = loc.hash;
  history.replaceState(null, "", pathname);

  if (pathname !== "/viewer") return undefined;
  if (search === "") {
    return NATIVE_LAUNCH.test(hash) ? { shareHref: href } : undefined;
  }
  return hash === "" && search.length <= MAX_POLICY_QUERY && PUBLIC_POLICY_QUERY.test(search)
    ? { shareHref: href }
    : undefined;
}
