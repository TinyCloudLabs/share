export interface CapturedLaunch {
  shareHref: string;
  readonly kind: "bearer" | "addressed";
}

const NATIVE_LAUNCH = /^#tc1=([^&]+)$/;
const SEALED_POLICY_FRAGMENT = /^#v=2&p=([A-Za-z0-9_-]+)$/;
const MAX_POLICY_FRAGMENT = 700_000;

/**
 * Capture the two cutover link forms, then remove their material from browser
 * history before configuration loading or network work:
 *
 * - `#tc1` is a secret bearer capability.
 * - `/s/inline#v=2&p=…` is a locally decrypted addressed-policy envelope.
 *
 * No plaintext `?tc2`, unresolved compact `/s/<cid>`, claim-secret, or
 * reload-cache form is accepted.
 */
export function captureAndScrubLaunch(loc: Location, history: History, _storage?: Storage): CapturedLaunch | undefined {
  const href = loc.href;
  const pathname = loc.pathname;
  const search = loc.search;
  const hash = loc.hash;
  history.replaceState(null, "", "/viewer");

  if (pathname === "/viewer" && search === "") {
    return NATIVE_LAUNCH.test(hash) ? { shareHref: href, kind: "bearer" } : undefined;
  }
  return pathname === "/s/inline" && search === "" && hash.length <= MAX_POLICY_FRAGMENT && SEALED_POLICY_FRAGMENT.test(hash)
    ? { shareHref: href, kind: "addressed" }
    : undefined;
}
