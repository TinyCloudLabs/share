export interface CapturedLaunch {
  shareHref: string;
  invite?: { readonly invitationId: string; readonly claimSecret: string };
}

const LAUNCH = /^#k=([A-Za-z0-9_-]{43})(?:&i=([A-Za-z0-9_-]{22})(?:&c=([A-Za-z0-9_-]{43}))?)?$/;
const INLINE_LAUNCH = /^#v=2&p=([A-Za-z0-9_-]+)$/;
const MAX_INLINE_LAUNCH_HASH = 700_000;

export function captureAndScrubLaunch(loc: Location, history: History): CapturedLaunch | undefined {
  const href = loc.href;
  const hash = loc.hash;
  // A malformed link may put a secret-looking value in the query. Remove the
  // query as well as the fragment before any later code can observe history.
  history.replaceState(null, "", loc.pathname);
  if (loc.search !== "") return undefined;
  if (hash === "" && /^\/s\/b[a-z2-7]+$/.test(loc.pathname)) {
    return { shareHref: href };
  }
  const match = LAUNCH.exec(hash);
  if (match !== null && match[1] !== undefined) {
    const parsed = new URL(href);
    parsed.hash = `#k=${match[1]}`;
    return {
      shareHref: parsed.href,
      ...(match[2] !== undefined ? { invite: Object.freeze({ invitationId: match[2], claimSecret: match[3] ?? "" }) } : {}),
    };
  }
  // Inline v2 links carry a bounded, canonical base64url payload in the
  // fragment. Preserve the complete fragment for the verifier; only the
  // compact invitation form may carry claim material.
  if (hash.length > MAX_INLINE_LAUNCH_HASH || INLINE_LAUNCH.test(hash) === false) return undefined;
  const parsed = new URL(href);
  parsed.hash = hash;
  return { shareHref: parsed.href };
}
