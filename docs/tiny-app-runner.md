# Opening an installed app: `/apps/run#<app_id>`

An app opened from [`/apps/`](apps-catalog.md) is saved in the person's own TinyCloud: its pinned
files under `<app_id>/app/` (`app.jsx` is its code, `manifest.json` says what it may use), its
`<app_id>/app/install.json` (`{source, digest, installed_at}`), and any notes under `<app_id>/knowledge/`. The runner opens it: it reads
those files, restores or obtains the app's own grant, reads the saved version, and runs `app.jsx` in the
[JSX sandbox](jsx-artifact-sharing.md), where it reaches the person's data only through a small
message bridge.

The runner is a Vite page (`apps/run/index.html`, `src/apps/run-*.ts`). The open starts when the page loads, with no click. Before OpenKey appears, the page loads the SDK and fetches only this origin's static files. No TinyCloud read or write occurs until the app's own session is restored or approved.

## What a person sees

1. **Disclosure, inline**: the app's name and description, what it can read and change (from the catalog's own manifest), and a provenance line that stays on screen the whole time: "This app was installed from `<repo>@<commit>` (version, bundle `<digest>`). It runs in a sandbox and can use only what's listed under "What this app can do"." Below it, always: "Some browser requests can't be blocked. Only open apps you trust." It is shown as the open starts, before OpenKey. There is no separate Continue step.
2. **First-open approval**: a new install asks once for the app's saved files and current-version grants. If the account already has its `applications` space, this is the only approval. If that space is missing, OpenKey then shows its normal "Create a new TinyCloud space" approval for `applications`; the app opens afterward. A routine reopen restores the app's saved session with no OpenKey request. A new approval is needed only for permissions the selected version adds beyond the saved grant.
3. **The app**, in its frame, under the page's own bar: the app name, "Open another app",
   "Sign out of this app", a status line (a live region), "What this app can do" and "What a
   sandboxed page can still reveal" (the same words as the viewer's notice). The bar is in the
   runner's document, outside the frame; the frame is an isolated, clipped box stacked below it.
4. **Plain screens** when the app cannot open: "This app asks for more than it did when you installed it", "Your saved copy
   of this app can't be used", "This app's code doesn't match the pinned version" (with Repair),
   "This app is temporarily unavailable" (the catalog's kill switch) or "Unavailable" (an entry with no `app.jsx`), each with the reason shown, "This version of the app isn't in the catalog any more" (with Uninstall),
   "Your session expired" (with Open again), and the usual OpenKey outcomes (cancelled, no
   answer in time, another request waiting, wrong account).

The session lasts one hour, or until its lease ends when the owner left automatic renewal on (90 days at most). At its end the frame is removed and the page says so; with a lease the saved session and lease are kept, and opening the app again restores through them with no approval. "Sign out of
this app" ends it earlier. The app-scoped session and any signed runtime grants for the selected
app version are stored in browser storage; the SDK validates them on restore. App files and notes
remain in TinyCloud.

### Why not the share viewer's notice

`src/viewer/artifact-notice.ts` is for pages a stranger sent: it can be dismissed and the
dismissal is remembered in `localStorage`. An installed app is the person's own saved copy of
code a catalog entry shipped; the runner's line says where it came from and what the sandbox is,
cannot be dismissed, and keeps the sandbox's privacy limits one click away in the viewer's words.

## Sign-in: the grant cap

The saved manifest is the person's to edit (their agent may rewrite it). It decides what the bridge
lets the app call, but never more than the catalog's manifest for the version they installed:

0. If there is no saved app session, check the current catalog entry's availability before signing in. With a saved session, defer the kill-switch check until the install record identifies the installed version.
1. A fresh install asks for the current version's app grant. A reopen restores the app's own persisted session with a narrow `get` on `<app_id>/app/install.json`; that same session reads the saved copy and resolves the catalog entry by `app_id` and `bundle.digest`. An unlisted digest stops with "This version of the app isn't in the catalog any more". Check the selected entry's kill switch before using it.
2. Load and verify the selected version's manifest from `/apps/b/<digest>/`. On a fresh install, the app approval covers that version's runtime grants, `get`, `list` and create-only `put` on `<app_id>/app/`, and create-only `put` on `<app_id>/knowledge/` (see [apps-catalog.md](apps-catalog.md)). If the primary `applications` space is missing, the SDK follows the production flow and asks separately to create that space; it does not retry the app approval. On reopen, restore the app-scoped session and request the selected version's grants on that same client; resources already covered by the signed grant or an existing runtime delegation do not prompt. Only an uncovered permission asks for approval. The runner's Trusted-Types-safe dialog lists only those additional permissions before the SDK creates a runtime grant. The same session saves missing files and runs the app. Sessions are app-scoped and persisted for one hour. The saved-copy read is bounded (64 files, 8 MB). The node's metadata does not give a file's size and `kv.get` buffers the whole value, so each file is fetched as a stream from a short-lived signed read URL and the read stops at the cap.

With no saved app session, the initial grant follows the current published version because the saved install record is not available until sign-in. The saved digest still selects the code and bridge permissions; an older bundle runs unchanged even if the current grant includes a newer permission.

3. **The pin**: hash every code file under `app/` (everything the catalog lists for the installed digest, except `knowledge/` and `manifest.json`; `install.json` is the install record) and compare with the catalog's sha256. A differing, missing or extra file is refused with the "This app's code doesn't match the pinned version" screen, which offers Repair. `knowledge/` stays the person's and is never hashed. `manifest.json` is not pinned: it is the person's to narrow, and the next step decides what it may ask for.
4. Re-validate the saved manifest with the SDK's `validateManifest`, then compare the SDK's own composed ReCap resources of both (`composeManifestRequest`). Every `(service, space, action, path)` of the saved manifest must be covered by one of the catalog's: same service and space, the action in the covering grant's actions, and the path equal, under a covering "/"-ending prefix, or covered by an empty path. Narrowing (fewer actions, longer paths, fewer grants) passes; anything wider is "This app asks for more than it did when you installed it". The first difference is shown.
5. Also refused: a delegation target (`did`), `secrets`, a space other than `applications`, a service outside key-value, SQL or the one sealing key, a custom folder prefix, a path with `..` or an empty segment. `includePublicSpace` is forced off and `expiry` to `1h`.
6. The bridge's allow-list is `makeAuthorizer` on the capped copy (`capGrants(saved, catalog).signing`). The frame's calls are checked against that list, not against the session.

### No signer escalation

With a saved session, the app client asks only for permissions resolved for the selected installed version, and only if the session does not already cover them. Without a saved session, the initial grant follows the current published version; the saved install record is read afterward, and the bridge remains capped to the selected version.
After the same-session permission check completes, the runner closes further signature
requests (`runner-signing-closed`, in the approval guard); bridge services invoke with the
session key only. A call outside the session's ReCap is refused by the node. The bridge
allow-list separately refuses the app frame's `app/` writes and allows `knowledge/` writes
only as the saved manifest grants them. The page, not the node, keeps installation writes
away from the app frame. `test/e2e-prod/runner-gate.mjs` (stage 6) runs the real data
adapter and bridge with the page's manifest check skipped, over a signer-less node-sdk
client restored from the app grant, against a real node.

### Repair

The refusal screen offers "Repair" (`/apps/#repair=<app_id>`), an inline panel on the app's page. The panel runs in repair
mode: one approval (put, delete and list on `<app_id>/app/`, 15 minutes), and the panel says
"This replaces your edited code. Your data is untouched." It writes the catalog's files for the
installed digest over the stored ones (`manifest.json` included, so a stray edit is undone too),
deletes any other file under `app/`, and never touches `install.json`, `knowledge/` or the
app's data. The bundle is fetched and verified against the catalog before OpenKey opens. A
version that has left the catalog has nothing to repair from: the page says so and offers Uninstall, which removes the app's code, manifest, install record and knowledge notes and keeps its data.

## The bridge

An installed app writes `import { sql, kv, file } from "@tinycloud/app"`. That module is a runner-only
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
| `seal.encrypt(value, context)` | `{value, context}` with a JSON value and the full record key | `{ok, sealed}` with an opaque string |
| `seal.decrypt(sealed, context)` | `{sealed, context}` with the returned string and the same record key | `{ok, value}` with the original JSON |
| `file.save(name, body, opts?)` | `{name, body, type?}`; body is a string or Uint8Array | `{ok}` once the offer is showing (see below) |

Every call resolves `{ok: true, …}` or `{ok: false, error: {code, message}}`; the bridge never
throws into the frame. Codes: `PERMISSION_DENIED`, `NOT_FOUND`, `PRECONDITION_FAILED`, `SQL_ERROR`,
`BAD_REQUEST`, `TOO_LARGE`, `BUSY`, `TIMEOUT`, `INTERNAL`, `NOT_CONNECTED`.

- **Paths** are relative to `<app_id>/`. A leading `/` is an absolute path in the space, allowed only
  where a manifest entry with `skipPrefix: true` covers it (the Recipes app reads the Health Log's
  database that way; the page lists it as "can read Health Log's database (whole database)").
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
  app's database. The details sheet already says "Can change or delete its own tables."
- **Limits**: 1 MB per call and per answer (strings counted as UTF-8; larger is `TOO_LARGE`), 4 calls in flight
  (the fifth is `BUSY`, not queued), 30 s per call. `TIMEOUT` says the call may still have been applied: read
  back before retrying a write. A call that timed out keeps its slot until it settles or 60 s pass.
- A frame message from the page's own window, another origin or a stranger frame, a wrong nonce, `v≠1`, an
  unknown type, extra keys or a repeated id is dropped without a reply.

### Encrypting app data

An app can use one key set aside for it on the owner's default encryption network. The catalog
manifest declares `keys_app_id: "xyz.tinycloud.share"` and one `keys` entry with
`path: "apps/xyz.tinycloud.share/<app_id>/seal-v1"` and `abilities: ["decrypt", "key.create"]`.
The runner shows this permission before sign-in. It asks for the key with the app's other grants
and the usual renewal option. A reopen uses an already approved key when the session holds it.

Import `seal` from `@tinycloud/app`. Use `seal.encrypt(value, context)` to encrypt a JSON
value and store the returned `sealed` string with the app's data. Use
`seal.decrypt(sealed, context)` to open it. Use the full record key as `context`, including the
app id and no leading slash. The key can be up to 512 characters. An encrypted value opens
only for the same record key, owner and space.

Share chooses the encryption key from the installed manifest and keeps its key material
outside the app. The saved manifest and the approved session must both allow the same key.
The app can encrypt up to 256 KiB of UTF-8 JSON and open an encrypted string up to 384 KiB.

### Saving a file: `file.save`

The frame has no downloads, so an app that builds a file (an export) hands it to the runner:
`file.save(name, body, opts?)` with `{name, body, type?}`. `body` is a string or Uint8Array; `opts.type` is
taken from the name's extension when it is left out. The call is an **offer**, not a save:

- The runner checks it first (`src/apps/save-file.ts`). Name: 1 to 100 characters; no slash, backslash,
  colon or other character Windows refuses, no control or invisible formatting character (direction
  overrides, zero-width, byte-order mark), no leading or trailing dot or space, no Windows device name, and it
  must end with the extension of its type. Type: only `text/plain` (`.txt`), `text/vcard` (`.vcf`),
  `text/markdown` (`.md`) and `application/json` (`.json`). Anything a browser or desktop would run or render
  (HTML, SVG, scripts, executables, archives) is not on the list. CSV is left off on purpose: a spreadsheet runs a
  cell that starts with `=`, `+`, `-` or `@` as a formula, and the runner does not rewrite an app's bytes. Adding a
  type is a reviewed change.
  Size: not empty, and within the 1 MB call limit (the name and type count too). A refused file is
  `BAD_REQUEST` (or `TOO_LARGE`) and nothing is shown.
- A valid file is shown in the runner's own bar, outside the frame (`src/apps/file-offer.ts`): "`<app>` offers a
  file to save: `<name>` (`<type>`, `<size>`). Nothing is saved unless you choose Save." with **Save** and
  **Dismiss**. The text is set with `textContent`; the live region announces it; focus does not move.
- **Save** is a click in the runner's own document, so the app cannot press it. It is inert for 0.7 s after the
  offer appears, because the offer pushes the app down and a click aimed at the app must not land on it. Where
  the browser has a save-file picker the owner picks the place; otherwise the browser's own download runs with
  the offered name. The runner then says what it did. Closing the picker keeps the offer.
- The call answers `{ok: true}` as soon as the offer is showing. A browser does not tell a page whether a
  download was kept, so "saved" is never claimed to the app.
- One offer waits at a time: another call before the owner chooses is `BUSY`, and so is one made within 2 s of the
  owner saving or dismissing (a double click or a re-offer loop cannot chain). The offer and its bytes are dropped
  when the owner saves or dismisses it, or when the app stops or fails, the owner signs out of the app or the
  session ends.
- It needs no manifest grant: the file is built from data the app already holds, and the owner's click is the
  consent. "What this app can do" says so in one fixed line. The offered name is the app's own text, so the
  owner decides on what they read.

## What an app can and cannot do

As in the sandbox (see [JSX artifact sharing](jsx-artifact-sharing.md)): run JavaScript, draw, keep state in
memory. The frame's CSP blocks every content and script request (`connect-src 'none'`, `default-src
'none'`, images and media from `data:`/`blob:` only), and there is no storage of the page's origin,
popups, forms, workers or downloads. Its data is what the bridge gives it, under the manifest the person signed.
This is **not** "no network access": some browser requests can't be blocked (see the known limits), so the page
tells people to install apps they trust.

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
  (`apps-runner-frame`, `jsx-sandbox`, `jsx-form-events`), the page (`apps-runner-view`, `apps-runner-page`), and
  the file offer (`apps-save-file`, `apps-runner-save-offer`).
- `TC500_NODE_WORKTREE=<tinycloud-node v1.21.0 tree> TC500_OPENCREDENTIALS_WORKTREE=<OpenCredentials 846c018 tree>
  npx tsx test/e2e-prod/runner-gate.mjs`: the native-stack gate described in its header (install both samples,
  open them, log a meal and read the row, cross-app read, widened and narrowed manifests, the pin (an edited
  `app.jsx` and an extra file are refused with one approval, Repair restores the catalog's files with one approval
  and the app opens, a removed version gets guidance and no Repair), a hostile app that the gate adds as a catalog
  entry (`test/fixtures/apps/hostile-app.jsx` + `leak-vectors.js`; a loopback listener must see no request,
  connection or UDP packet), the node refusing calls forced past the page, sign-out, expiry, every state at
  390/1440 px in light and dark with axe). `RUNNER_SHOT_DIR` saves the screenshots.

## Known limits

- A fresh install asks once for its version's grant. A routine reopen reads `install.json` through the app's persisted session and asks only for permissions not already covered; it makes no OpenKey request when the installed version's grant is covered.
- An installed version that has left the catalog cannot be opened or repaired (its code can't be checked); the page shows what to delete.
- An app can still reveal that you opened it (your IP address and the time), and by trying to open another page (`location`, a followed
  link) it can make your browser look up and connect to an address it picks, which can carry a little data. Measured: no HTTP request is
  sent, one TCP connection is made. Nothing inside the frame can stop this.
- Some other browser requests can still carry what the app reads to an address it picks: the CSP does not govern a prerender, a preconnect,
  a DNS prefetch or `<a ping>`, and the guard that refuses them is best effort. These paths are known closed (the probe sees nothing); same-realm
  code may find others. Open apps you trust.
- Node error text is not shown to the app, except a SQL error's message, which is scrubbed of tokens, identifiers and stack lines.
- The catalog's two sample bundles still say "no network" in a code comment and a knowledge file: they are pinned by digest and change with the next catalog release.
- The pin covers the code, not `manifest.json` (capped by the grant check) or `knowledge/` (the person's).
- The first screen shows the catalog's manifest; once the saved copy is read, the page shows the saved one.
- A runtime busy loop in an app can freeze the tab until the sandbox moves to its own site (S9).
