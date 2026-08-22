export interface CapturedLaunch {
  shareHref: string;
  invite?: { readonly invitationId: string; readonly claimSecret: string };
}

const LAUNCH = /^#k=([A-Za-z0-9_-]{43})(?:&i=([A-Za-z0-9_-]{22})(?:&c=([A-Za-z0-9_-]{43}))?)?$/;
const INLINE_LAUNCH = /^#v=2&p=([A-Za-z0-9_-]+)$/;
const NATIVE_LAUNCH = /^#tc1=([^&]+)$/;
const MAX_INLINE_LAUNCH_HASH = 700_000;
const RELOAD_KEY_PREFIX = "tinycloud.share.bearer-key.v1:";

function reloadKey(pathname: string): string | undefined {
  const match = /^\/s\/(b[a-z2-7]+)$/.exec(pathname);
  return match?.[1] === undefined ? undefined : `${RELOAD_KEY_PREFIX}${match[1]}`;
}

function rememberBearerKey(storage: Storage | undefined, pathname: string, key: string): void {
  const name = reloadKey(pathname);
  if (storage === undefined || name === undefined) return;
  try { storage.setItem(name, key); } catch { /* Storage can be disabled. The original link still opens. */ }
}

function recalledBearerHref(storage: Storage | undefined, href: string, pathname: string): string | undefined {
  const name = reloadKey(pathname);
  if (storage === undefined || name === undefined) return undefined;
  let key: string | null;
  try { key = storage.getItem(name); } catch { return undefined; }
  if (key === null || !/^[A-Za-z0-9_-]{43}$/.test(key)) return undefined;
  const parsed = new URL(href);
  parsed.hash = `#k=${key}`;
  return parsed.href;
}

export function captureAndScrubLaunch(loc: Location, history: History, storage?: Storage): CapturedLaunch | undefined {
  const href = loc.href;
  const hash = loc.hash;
  // A malformed link may put a secret-looking value in the query. Remove the
  // query as well as the fragment before any later code can observe history.
  history.replaceState(null, "", loc.pathname);
  if (loc.search !== "") return undefined;
  // Native SharingService links are rooted at the viewer and carry all
  // receiver key/delegation material in one opaque fragment. Do not accept
  // pre-cutover path or query variants.
  if (loc.pathname === "/") {
    const native = NATIVE_LAUNCH.exec(hash);
    if (native !== null) {
      const parsed = new URL(href);
      const token = new URLSearchParams(hash.slice(1)).get("tc1");
      if (token === null || token.length === 0) return undefined;
      parsed.hash = `tc1=${encodeURIComponent(token)}`;
      return { shareHref: parsed.href };
    }
  }
  if (hash === "" && /^\/s\/b[a-z2-7]+$/.test(loc.pathname)) {
    return { shareHref: recalledBearerHref(storage, href, loc.pathname) ?? href };
  }
  const match = LAUNCH.exec(hash);
  if (match !== null && match[1] !== undefined) {
    const parsed = new URL(href);
    parsed.hash = `#k=${match[1]}`;
    // Only a plain bearer key is retained. Invitation IDs and claim secrets
    // remain memory-only, while compact bearer links can survive a reload in
    // this tab after their fragment has been scrubbed from the address bar.
    if (match[2] === undefined) rememberBearerKey(storage, loc.pathname, match[1]);
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
