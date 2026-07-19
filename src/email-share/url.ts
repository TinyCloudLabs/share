export interface CapturedLaunch {
  readonly shareHref: string;
  readonly invite?: { readonly invitationId: string; readonly claimSecret: string };
}

const LAUNCH = /^#k=([A-Za-z0-9_-]{43})(?:&i=([A-Za-z0-9_-]{22})&c=([A-Za-z0-9_-]{43}))?$/;

export function captureAndScrubLaunch(loc: Location, history: History): CapturedLaunch | undefined {
  const href = loc.href;
  const hash = loc.hash;
  // A malformed link may put a secret-looking value in the query. Remove the
  // query as well as the fragment before any later code can observe history.
  history.replaceState(null, "", loc.pathname);
  if (loc.search !== "" || hash.length > 160) return undefined;
  const match = LAUNCH.exec(hash);
  if (match === null || match[1] === undefined) return undefined;
  const parsed = new URL(href);
  parsed.hash = `#k=${match[1]}`;
  return {
    shareHref: parsed.href,
    ...(match[2] !== undefined && match[3] !== undefined ? { invite: Object.freeze({ invitationId: match[2], claimSecret: match[3] }) } : {}),
  };
}
