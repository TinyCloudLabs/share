# User-content origin

Sandbox documents (`/jsx-sandbox.html`, `/artifact-sandbox.html`,
`/mermaid-sandbox.html`) and the JSX library files (`/assets/jsx-runtime/*`) can be
served from a separate origin, for example `https://usercontent.tinycloud.xyz`.

## Configuration

- Viewer build: `VITE_USER_CONTENT_ORIGIN` (empty by default = same origin as today).
  `src/viewer/user-content-origin.ts` is the only place the value is read; every
  frame URL and library URL is built from it.
- User-content build: `npm run build:usercontent` writes `dist-usercontent/`:
  the three documents, `assets/jsx-runtime/*.js`, `manifest.json`, `NOTICE.txt` and
  `_headers`. Nothing else. `USER_CONTENT_VIEWER_ORIGIN` (default
  `https://share.tinycloud.xyz`) is the one origin allowed to frame the documents
  and to read the files.
- With the origin set, the viewer build ships none of those files, its
  `_headers` drops the sandbox routes, and its CSP (header and `viewer/index.html`
  meta) names exactly that origin in `frame-src` and `connect-src`.

## Deploying

1. Deploy `dist-usercontent` to the user-content host first
   (build command `npm ci && npm run build:usercontent`, output `dist-usercontent`).
2. Then deploy the viewer with `VITE_USER_CONTENT_ORIGIN` set.

The viewer embeds the sha256 of every library file and refuses a file that does
not match (it shows "This artifact viewer is updating"). File names carry the
hash, and builds are deterministic for one commit, so the two projects must be
built from the same commit. Roll back in the reverse order.

## Headers on the user-content host

- `/*`: `! Access-Control-Allow-Origin` (Pages adds `*` by default), no-cache,
  `default-src 'none'; frame-ancestors 'none'`, COOP same-origin, a restrictive
  Permissions-Policy, no referrer, nosniff. No cookies are ever set and there is no API.
- Each sandbox document: its own CSP (the same string as its meta tag) plus
  `frame-ancestors <viewer origin>`, in place of the site-wide one. No
  X-Frame-Options (it cannot name a cross-origin parent).
- `/assets/jsx-runtime/*` and `/manifest.json`: `Access-Control-Allow-Origin:
  <viewer origin>` and `Vary: Origin`; the files are `immutable`. The viewer fetches
  them with `mode: "cors"`, `credentials: "omit"` and no referrer.
- Cloudflare's zone-wide Email Obfuscation and Browser Integrity Check are not
  scoped per host: a test keeps address-shaped strings out of the shipped files.

## Why a subdomain is acceptable now

The frames are sandboxed without `allow-same-origin`, so their origin is `null`
whatever host serves them. Cookies for `.tinycloud.xyz` are not readable by an
opaque-origin script, and its requests are cross-site, so SameSite cookies are not
sent with them. The remaining weakness: a sandbox escape would land in the
user-content origin, which is the same site as `share.tinycloud.xyz`, so
`Domain=.tinycloud.xyz` cookies and the Lax/Strict same-site CSRF defences are the
exposure. A separate registrable domain, planned for live/public content, removes it.

Moving the origin does not change the network claim: a separate origin is
isolation, not egress control: prerender, preconnect, navigation attempts,
dns-prefetch and WebRTC can still reach out from a frame on any origin (see
"Privacy" in `jsx-artifact-sharing.md`).
