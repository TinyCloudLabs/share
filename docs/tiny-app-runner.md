# Opening an installed app: `/apps/run#<app_id>`

An app opened from [`/apps/`](apps-catalog.md) is saved in the person's own TinyCloud: its pinned
files under `<app_id>/app/` (`app.jsx` is its code, `manifest.json` says what it may use), its
`<app_id>/app/install.json` (`{source, digest, installed_at}`), and any notes under `<app_id>/knowledge/`. The runner opens it: it reads
those files, signs in for exactly what the manifest asks, and runs `app.jsx` in the
[JSX sandbox](jsx-artifact-sharing.md), where it reaches the person's data only through a small
message bridge.

The runner is a Vite page (`apps/run/index.html`, `src/apps/run-*.ts`). Until the person clicks
Continue it loads no SDK and makes no request beyond this origin's static files.

## What a person sees

1. **Start screen**: the app's name and description, what it can read and change (from the
   catalog's own manifest, shown before anything is signed), and a provenance line that stays
   on screen the whole time: "This app was installed from `<repo>@<commit>` (version, bundle
   `<digest>`). It runs in a sandbox and can use only what's listed under "What this app can
   do"." Below it, always: "Some browser requests can't be blocked. Only open apps you trust. Beta:
   use sample data only."
2. **Two OpenKey approvals**, one at a time, each named in the status line: (1 of 2) so
   Share can read the app from the person's TinyCloud and save any missing files, (2 of 2) to start it with the
   permissions listed on the page. OpenKey connects once.
3. **The app**, in its frame, under the page's own bar: the app name, "Open another app",
   "Sign out of this app", a status line (a live region), "What this app can do" and "What a
   sandboxed page can still reveal" (the same words as the viewer's notice). The bar is in the
   runner's document, outside the frame; the frame is an isolated, clipped box stacked below it.
4. **Plain screens** when the app cannot open: "This app asks for more than it did when you installed it", "Your saved copy
   of this app can't be used", "This app's code doesn't match the pinned version" (with Repair),
   "This app is temporarily unavailable" (the catalog's kill switch), "This version of the app isn't in the catalog any more",
   "Your session expired: open the app again", and the usual OpenKey outcomes (cancelled, no
   answer in time, another request waiting, wrong account).

The session lasts one hour. At its end the frame is removed and the page says so. "Sign out of
this app" ends it earlier. Nothing is stored in the browser, and no delegation outlives the tab.

### Why not the share viewer's notice

`src/viewer/artifact-notice.ts` is for pages a stranger sent: it can be dismissed and the
dismissal is remembered in `localStorage`. An installed app is the person's own saved copy of
code a catalog entry shipped; the runner's line says where it came from and what the sandbox is,
cannot be dismissed, and keeps the sandbox's privacy limits one click away in the viewer's words.

## Sign-in: the grant cap

The saved manifest is the person's to edit (their agent may rewrite it), and it decides what the
app is signed for, but never more than the catalog's manifest for the version they installed:

0. The catalog's kill switch (`assertAvailable`, from the apps catalog) is checked before any
   sign-in: a disabled entry opens nothing.
1. Read everything under `<app_id>/app/` with a first sign-in that asks for `get` and `list` on
   `<app_id>/app/`, and create-only `put` on `<app_id>/app/` and `<app_id>/knowledge/` for the save
   step (see [apps-catalog.md](apps-catalog.md)), 15 minutes (under share's own identity, so the person's apps list gains no
   record named after the app). That session ends before the next sign-in. The read is bounded
   (64 files, 8 MB). The node's metadata does not give a file's size and `kv.get` buffers the whole value, so each file is fetched as a
   stream from a short-lived signed read URL (a `get`) and the read stops, cancelling the stream, at the first byte past the cap: a 1 GB
   `app/x` is refused after a few chunks, not downloaded. A listing that does not fit counts as a mismatch.
2. Find the catalog entry whose `app_id` and `bundle.digest` equal the install record's. None:
   "isn't in the catalog any more", nothing signed. **The pin**: on every open, before any runtime
   session, bridge or frame, hash every code file under `app/` (everything the catalog lists for
   that digest except `knowledge/` and `manifest.json`; `install.json` is the install record) and
   compare with the catalog's sha256 for the installed digest. A differing, missing or extra file is
   refused with "This app's code doesn't match the pinned version. Remove it and install again."
   `knowledge/` stays the person's: it is never hashed. `manifest.json` is not pinned either: it is
   the person's to narrow, and the cap below decides what it may ask for. Then fetch that entry's
   manifest from `/apps/b/<digest>/` and check it against the catalog's sha256 (as the install does).
3. Re-validate the saved manifest with the SDK's `validateManifest`, then compare the SDK's own
   composed ReCap resources of both (`composeManifestRequest`, with the account registry grants the
   sign-in always adds). Every `(service, space, action, path)` of the saved manifest must be covered by
   one of the catalog's: same service and space, the action in the covering grant's actions, and
   the path equal, under a covering "/"-ending prefix, or covered by an empty path. Narrowing
   (fewer actions, longer paths, fewer grants) passes; anything wider is "asks for more than it did
   when you installed it" and stops after one approval. The first difference is shown.
4. Also refused: a delegation target (`did`), `secrets`, a space other than `applications`, a
   service other than key-value and SQL, a custom folder prefix, a path with `..` or an empty
   segment. `includePublicSpace` is forced off and `expiry` to `1h`.
5. Sign in with that manifest (`signInWithManifest`, src/share/openkey-session.ts, unchanged),
   one hour, `persistSession: false`.

### No signer escalation

A wallet-mode client signs for more than its session covers when asked. The runner's web client has
OpenKey as its signer, so once the runtime sign-in finishes every signature request is refused
(`runner-signing-closed`, in the approval guard both the provider and the SDK's sign callback go
through), and the services the bridge uses invoke with the session key only. A call outside the
session's ReCap therefore goes to the node and is refused there. `test/e2e-prod/runner-gate.mjs`
runs the real data adapter and bridge with the page's manifest check skipped, over a signer-less
node-sdk client restored from the manifest-scoped session, against a real node, and asserts the
node refuses every call the manifest does not cover.

Residual: the sign-in helper hard-codes `includeAccountRegistryPermissions: true`
(`src/share/openkey-session.ts`), so the session also carries `account`-space registry permissions (kv
`applications/`, `spaces/`, `system/bootstrap/complete`, the account index database). The runner
cannot opt out without changing the helper, so it does not. The bridge cannot name the `account`
space, but if the runner page's checks failed, the node would not refuse a call in those prefixes.

### Repair

The refusal screen offers "Repair" (`/apps/#repair=<app_id>`). The Repair sheet runs in repair
mode: one approval (put, delete and list on `<app_id>/app/`, 15 minutes), and the sheet says it
"Repair replaces the app's code files with the pinned version. Your data is untouched." It writes the catalog's files for the
installed digest over the stored ones (`manifest.json` included, so a stray edit is undone too),
deletes any other file under `app/`, and never touches `install.json`, `knowledge/` or the
app's data. The bundle is fetched and verified against the catalog before OpenKey opens. A
version that has left the catalog has nothing to repair from: the page says so and shows what to
delete (`tinycloud kv list --space applications --prefix <app_id>/app/`, then
`tinycloud kv delete --space applications <each key listed>`).

## The bridge

An installed app writes `import { sql, kv } from "@tinycloud/app"`. That module is a runner-only
library file (`JSX_MODULE_SPECS`, `runnerOnly`): the share viewer never loads it, so on a shared
page the import is an unknown library. It posts `{v:1, type:"cap/<op>", id, args}` to the frame's
parent and resolves with the answer. It holds nothing secret and decides nothing.

```
child (the app + @tinycloud/app)
  → bridge document   known op, plain data ≤ 1 MB, ≤ 4 in flight, {v,type,id,args} only; stamps the nonce
    → runner page     src/apps/bridge.ts: the ONE handler registered through createJsxSandbox({ onCapability })
```

Both hops keep the sandbox's checks: `event.source` identity, `event.origin === "null"`, the nonce
(page ↔ bridge), `v:1`, a type allowlist, exact key sets. A reply is `{v,type:"cap/result",nonce,id,result}`.
Nothing about the session, its keys, the owner, the node or any URL is in any frame message.

### Operations

| Call | Arguments | Result |
| --- | --- | --- |
| `kv.get(key)` | `{key}` | `{ok, bytes: Uint8Array, contentType?}` |
| `kv.put(key, body, opts?)` | `{key, body, contentType?, ifNoneMatch?: true}`; body is a string or Uint8Array | `{ok}` |
| `kv.list(prefix = "")` | `{key}` | `{ok, keys, truncated}` (keys in the same relative form) |
| `kv.del(key)` | `{key}` | `{ok}` |
| `sql.query(db, text, params = [])` | `{db, sql, params}` | `{ok, columns, rows, rowCount}` |
| `sql.execute(db, text, params = [])` | `{db, sql, params}` | `{ok, changes, lastInsertRowId}` |

Every call resolves `{ok: true, …}` or `{ok: false, error: {code, message}}`; the bridge never
throws into the frame. Codes: `PERMISSION_DENIED`, `NOT_FOUND`, `PRECONDITION_FAILED`, `SQL_ERROR`,
`BAD_REQUEST`, `TOO_LARGE`, `BUSY`, `TIMEOUT`, `INTERNAL`, `NOT_CONNECTED`.

- **Paths** are relative to `<app_id>/`. A leading `/` is an absolute path in the space, allowed only
  where a manifest entry with `skipPrefix: true` covers it (the Recipes sample reads the Health Log's
  database that way; the page lists it as "can read Health Log (sample)'s database (whole database)").
  Keys and database names refuse `..`, `.` and empty segments, control characters and backslashes.
- **The check order**: a known operation and key set; id and plain-data shape; size; session still live;
  in-flight cap; per-operation validation; statement class; then `(service, path, action)` against the
  app's resolved manifest, **before any SDK call**. That check is a UX and defence layer: the node
  enforces by granted ability and prefix and is the boundary.
- **SQL**: `sql.query` runs exactly one read-only statement. The parent classifies the statement
  itself (`src/apps/sql-class.ts`, ported from the kit's reference `classifySql`) because the node
  enforces by ability, not call name: refused are more than one statement, `WITH … INSERT|UPDATE|DELETE`,
  `load_extension` (also quoted), `PRAGMA`, `ATTACH`, `DETACH`, `VACUUM`, characters SQLite does not treat
  as whitespace but JavaScript does, and anything that is not SELECT / VALUES / read-only WITH / EXPLAIN.
  The class names the ability the manifest must grant: read, write or schema.
- **`sql.execute`** runs one write or DDL statement, and only in the app's **own** databases (a relative
  `db`). TC-1581 (the node lets `sql/write` run DDL) is not fixed here, but the bridge asks for `schema`
  for a CREATE/DROP/ALTER, so an app cannot do DDL on a write-only grant, and it cannot be the way into another
  app's database. The details sheet already says "This app can change or delete its own tables."
- **Limits**: 1 MB per call and per answer (strings counted as UTF-8; larger is `TOO_LARGE`), 4 calls in flight
  (the fifth is `BUSY`, not queued), 30 s per call. `TIMEOUT` says the call may still have been applied: read
  back before retrying a write. A call that timed out keeps its slot until it settles or 60 s pass.
- A frame message from the page's own window, another origin or a stranger frame, a wrong nonce, `v≠1`, an
  unknown type, extra keys or a repeated id is dropped without a reply.

## What an app can and cannot do

As in the sandbox (see [JSX artifact sharing](jsx-artifact-sharing.md)): run JavaScript, draw, keep state in
memory. The frame's CSP blocks every content and script request (`connect-src 'none'`, `default-src
'none'`, images and media from `data:`/`blob:` only), and there is no storage of the page's origin,
popups, forms, workers or downloads. Its data is what the bridge gives it, under the manifest the person signed.
This is **not** "no network access": some browser requests can't be blocked (see the known limits), so the page
tells people to install apps they trust and, in the beta, to use sample data only.

The static scan in the kit's samples is defence in depth only: the sandbox is the boundary.

### Frame hardening (best effort)

The CSP stops every content and script request, but **no CSP directive governs a prerender** (a `<link rel=prerender>` sends a GET
with whatever query the page chose), a preconnect, a DNS prefetch, `<a ping>` or WebRTC. That is why the frame's runtime also refuses the
elements and attributes that start them (`src/artifact/jsx-runtime/url-guard.ts`). For an installed app this matters: a prerender can carry
data the app read through the bridge to an address it picks.

Two layers:

- an element-type and attribute allow-list: `<base>`, `<script>`, `<iframe>`, `<frame>`, `<object>`, `<embed>`, `<portal>`,
  `<meta http-equiv>`/`url=`, `<template shadowrootmode>`, and any `<link>`, `<img>`, `<source>`, `<video>`/`<audio>`/`<track>`,
  `<form action>`, `<input>`/`<button formaction>`, `<a ping>`, SVG `href` or `style` whose URL is not `data:`, `blob:` or `#` are
  refused. React elements are vetted when created (`createElement`, `jsx`, `jsxs`, `jsxDEV`: a refused element renders nothing).
  In the DOM, each path known to put a node or an attribute value somewhere is vetted BEFORE it applies:
  - nodes: `appendChild`/`insertBefore`/`replaceChild`; `before`/`after`/`replaceWith` on `Element`, `Text`, `Comment` (`CharacterData`) and
    `DocumentType`; `append`/`prepend`/`replaceChildren` on `Element`, `Document` and `DocumentFragment` (shadow roots included);
    `insertAdjacentElement`; `Range.insertNode`/`surroundContents`. An inserted subtree is swept including `<template>` content and shadow
    roots (open, or closed ones the page made with `attachShadow`);
  - HTML strings: `innerHTML`/`outerHTML` (elements and shadow roots), `insertAdjacentHTML`, `setHTML`/`setHTMLUnsafe`, `Document.parseHTMLUnsafe`,
    `createContextualFragment`, `execCommand('insertHTML')` are cleaned through an inert parse; declarative shadow DOM
    (`<template shadowrootmode>`) is refused. `document.write` is refused whole (one parser spans calls, so a tag could be split; after load it
    would also replace the document);
  - attributes: `setAttribute(NS)`, `setAttributeNode(NS)`, `NamedNodeMap.setNamedItem(NS)`, an `Attr`'s `value`/`nodeValue`/`textContent` and the
    reflected URL properties (`link.href`, `img.src`, `a.ping`, ...);
- a MutationObserver backstop (child lists and the URL attributes, shadow roots included) that removes whatever still gets in. It runs
  AFTER the browser may already have started a prerender or a preconnect, so it is not what closes the known paths: the patches are.

**Best effort: these paths are known closed; same-realm code may find others.** The guard is not a boundary; the CSP is one for everything it
governs, and it does not govern the requests above. Not patched: `Element.moveBefore` (it only moves a node already in the document); an
HTML string sink that a newer browser adds. A follow-up could add a Trusted Types default policy (`require-trusted-types-for 'script'`), which closes
the HTML-string sinks in the browser itself but not the node and attribute sinks, and needs the runtime's own `eval` moved onto a policy.

`test/fixtures/apps/leak-vectors.js` is the PROBE: 147 vectors (every path above with each of prerender, prefetch, preconnect, dns-prefetch, preload and
modulepreload links, `<a ping>`, `<img>`, `<picture>`, `<video>`, `<audio>`, `<track>`, `<iframe>`, `<object>`, `<embed>`, `<form>`, `<meta refresh>`, `<base>`,
`<script>`, speculation rules, WebTransport, XSLT output, a custom element with a closed shadow root, declarative shadow DOM; CSS `url()`/`@import`/`image-set`, fonts;
fetch, XHR, WebSocket, EventSource, `sendBeacon`, `import()`, workers, WebRTC). `test/e2e-jsx.mjs` (a shared page) and the runner gate (a hostile catalog
app that has read a row through the bridge) run it against a loopback listener (HTTP, upgrade, UDP) and assert ZERO hits for every vector. The vectors that
once leaked (`Text.after`, `Attr` edits, `setAttributeNode`, declarative shadow DOM, an XSLT fragment) are part of it.

### Sandbox page headers (reviewed)

`JSX_SANDBOX_HTTP_HEADERS` (`src/viewer/jsx-frame.ts`): the CSP above plus `frame-ancestors 'self'`,
a Permissions-Policy that turns off the sensor, payment and capture features
(`src/viewer/sandbox-permissions.ts`), `Referrer-Policy: no-referrer`, `X-Frame-Options: SAMEORIGIN`,
`X-Content-Type-Options: nosniff` and `Cache-Control: no-store`. Reviewed for this slice, no change needed:
the policies that matter for leaks are already closed (`connect-src`, `form-action`, `frame-src`, `base-uri`,
`worker-src`, `object-src`, `img-src`, `media-src`, `font-src`). None of them, and no header, governs a prerender, a preconnect, a DNS
prefetch or `<a ping>`: the frame hardening above is what stops those. `X-DNS-Prefetch-Control` was not added: it does not stop
the lookup a navigation attempt makes, and the hint is already refused.

## Deploying

`apps/run/index.html` is a new Vite input (`appsRun`) and `public/_redirects` has
`/apps/run /apps/run/ 200` (no `.html` rewrite). With a user-content origin
(`VITE_USER_CONTENT_ORIGIN`) the build adds it to the page's `frame-src` and `connect-src` like the viewer's.
The `@tinycloud/app` library file is built, hashed and served with the other JSX library files, and
`npm run build:usercontent` carries it.

## Tests

- `npm test`: the classifier (`apps-sql-class`), the grant cap and stored-app checks (`apps-runner-grants`), the
  bridge handler with a fake data port (`apps-runner-bridge`), the frame side and the client module
  (`apps-runner-frame`, `jsx-sandbox`, `jsx-form-events`), the page (`apps-runner-view`, `apps-runner-page`).
- `TC500_NODE_WORKTREE=<tinycloud-node v1.21.0 tree> TC500_OPENCREDENTIALS_WORKTREE=<OpenCredentials 846c018 tree>
  npx tsx test/e2e-prod/runner-gate.mjs`: the native-stack gate described in its header (install both samples,
  open them, log a meal and read the row, cross-app read, widened and narrowed manifests, the pin (an edited
  `app.jsx` and an extra file are refused with one approval, Repair restores the catalog's files with one approval
  and the app opens, a removed version gets guidance and no Repair), a hostile app that the gate adds as a catalog
  entry (`test/fixtures/apps/hostile-app.jsx` + `leak-vectors.js`; a loopback listener must see no request,
  connection or UDP packet), the node refusing calls forced past the page, sign-out, expiry, every state at
  390/1440 px in light and dark with axe). `RUNNER_SHOT_DIR` saves the screenshots.

## Known limits

- Opening needs two approvals: the saved copy cannot be read before signing in, and the app's own session
  must not exist until it has been checked. A persisted per-app session is a later slice.
- An installed version that has left the catalog cannot be opened or repaired (its code can't be checked); the page shows what to delete.
- An app can still reveal that you opened it (your IP address and the time), and by trying to open another page (`location`, a followed
  link) it can make your browser look up and connect to an address it picks, which can carry a little data. Measured: no HTTP request is
  sent, one TCP connection is made. Nothing inside the frame can stop this.
- Some other browser requests can still carry what the app reads to an address it picks: the CSP does not govern a prerender, a preconnect,
  a DNS prefetch or `<a ping>`, and the guard that refuses them is best effort. These paths are known closed (the probe sees nothing); same-realm
  code may find others. Open apps you trust; in the beta, use sample data only.
- Node error text is not shown to the app, except a SQL error's message, which is scrubbed of tokens, identifiers and stack lines.
- The catalog's two sample bundles still say "no network" in a code comment and a knowledge file: they are pinned by digest and change with the next catalog release.
- The pin covers the code, not `manifest.json` (capped by the grant check) or `knowledge/` (the person's).
- The first screen shows the catalog's manifest; once the saved copy is read, the page shows the saved one.
- A runtime busy loop in an app can freeze the tab until the sandbox moves to its own site (S9).
