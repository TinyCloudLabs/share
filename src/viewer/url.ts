/**
 * Location/history handling for the viewer entry. Split from main.ts so it
 * is testable without executing the boot side effect.
 */

/**
 * Scrub the key fragment out of the address bar AND the current history
 * entry. The `#k=` fragment is the AES key: after it has been captured into
 * a string for parsing, leaving it in `location.hash` means any later
 * same-origin XSS (or anything that reads the history entry) can recover the
 * full key. Must be called BEFORE any fetch or render happens.
 *
 * `history.replaceState` rewrites the current entry in place, so no history
 * entry retains the fragment. (JS strings are immutable and GC'd, so the
 * transient href string cannot be zeroed — the Uint8Array key parsed from it
 * is the only zeroable copy, and resolve.ts zeroes it on every return path.)
 */
export function scrubKeyFragment(loc: Location, hist: History): void {
  if (loc.hash === "") return;
  hist.replaceState(null, "", `${loc.pathname}${loc.search}`);
}

/**
 * parseShareUrl is strictly https-only (correct for real links). The Vite
 * dev server runs plain http on localhost, so — in DEV BUILDS, for LOOPBACK
 * HOSTS ONLY — rewrite the scheme so local development is possible. The
 * caller passes `import.meta.env.DEV`; in production builds this branch is
 * dead code and every http URL fails closed in parseShareUrl. The rewrite
 * preserves pathname, search, AND hash so nothing is silently dropped
 * (a query string must still reach parseShareUrl and be rejected there).
 */
export function hrefForParse(loc: Location, isDevBuild: boolean): string {
  if (
    isDevBuild &&
    loc.protocol === "http:" &&
    (loc.hostname === "localhost" || loc.hostname === "127.0.0.1")
  ) {
    return `https://${loc.host}${loc.pathname}${loc.search}${loc.hash}`;
  }
  return loc.href;
}
