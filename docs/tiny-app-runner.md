# Opening an installed app: `/apps/run#<app_id>`

An app installed from [`/apps/`](apps-catalog.md) is three files in the person's own TinyCloud:
`<app_id>/app/app.jsx` (its code), `<app_id>/app/manifest.json` (what it may use) and
`<app_id>/app/install.json` (`{source, digest, installed_at}`). The runner opens it: it reads
those files, signs in for exactly what the manifest asks, and runs `app.jsx` in the
[JSX sandbox](jsx-artifact-sharing.md), where it reaches the person's data only through a small
message bridge.

The runner is a Vite page (`apps/run/index.html`, `src/apps/run-*.ts`). Until the person clicks
Continue it loads no SDK and makes no request beyond this origin's static files.

## What a person sees

1. **Start screen**: the app's name and description, what it can read and change (from the
   catalog's own manifest, shown before anything is signed), and a provenance line that stays
   on screen the whole time: "This app was installed from `<repo>@<commit>` (version, bundle
   `<digest>`). It runs in a sandbox with no network access and can use only what's listed
   under "What this app can do"."
2. **Two OpenKey approvals**, one at a time, each named in the status line: (1 of 2) so
   Share can read the app from the person's TinyCloud, (2 of 2) to start it with the
   permissions listed on the page. OpenKey connects once.
3. **The app**, in its frame, under the page's own bar: the app name, "Open another app",
   "Sign out of this app", a status line (a live region), "What this app can do" and "What a
   sandboxed page can still reveal" (the same words as the viewer's notice). The bar is in the
   runner's document, outside the frame; the frame is an isolated, clipped box stacked below it.
4. **Plain screens** when the app cannot open: "This app needs to be installed first" (with a
   link to `/apps/`), "This app asks for more than it did when you installed it", "Your saved copy
   of this app can't be used", "This version of the app isn't in the catalog any more",
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

1. Read `<app_id>/app/{install.json,manifest.json,app.jsx}` with a first sign-in that asks only
   for `get` on `<app_id>/app/` (under share's own identity, so the person's apps list gains no
   record named after the app). That session ends before the next sign-in.
2. Find the catalog entry whose `app_id` and `bundle.digest` equal the install record's. None:
   "isn't in the catalog any more", nothing signed. Fetch that entry's manifest from
   `/apps/b/<digest>/` and check it against the catalog's sha256 (as the install does).
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

Residual: the sign-in helper always adds the account registry grants, so the session also carries
`account`-space registry permissions (kv `applications/`, `spaces/`, `system/bootstrap/complete`,
the account index database). The bridge cannot name the `account` space, but if the runner page's
checks failed, the node would not refuse a call in those prefixes. A follow-up on the helper
(an option to leave them out) removes this.

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
  app's database. The install sheet already says "This app can change or delete its own tables."
- **Limits**: 1 MB per call and per answer (strings counted as UTF-8; larger is `TOO_LARGE`), 4 calls in flight
  (the fifth is `BUSY`, not queued), 30 s per call. `TIMEOUT` says the call may still have been applied: read
  back before retrying a write. A call that timed out keeps its slot until it settles or 60 s pass.
- A frame message from the page's own window, another origin or a stranger frame, a wrong nonce, `v≠1`, an
  unknown type, extra keys or a repeated id is dropped without a reply.

## What an app can and cannot do

As in the sandbox (see [JSX artifact sharing](jsx-artifact-sharing.md)): run JavaScript, draw, keep state in
memory. No network (`connect-src 'none'`), no storage of the page's origin, no navigation, popups, forms,
workers or downloads. Its data is what the bridge gives it, under the manifest the person signed.

The static scan in the kit's samples is defence in depth only: the sandbox is the boundary.

## Deploying

`apps/run/index.html` is a new Vite input (`appsRun`) and `public/_redirects` has
`/apps/run /apps/run/ 200` (no `.html` rewrite). With a user-content origin
(`VITE_USER_CONTENT_ORIGIN`) the build adds it to the page's `frame-src` and `connect-src` like the viewer's.
The `@tinycloud/app` library file is built, hashed and served with the other JSX library files, and
`npm run build:usercontent` carries it.

## Known limits

- Opening needs two approvals: the saved copy cannot be read before signing in, and the app's own session
  must not exist until it has been checked. A persisted per-app session is a later slice.
- An installed version that has left the catalog cannot be opened (its permissions can't be checked).
- The first screen shows the catalog's manifest; once the saved copy is read, the page shows the saved one.
- A runtime busy loop in an app can freeze the tab until the sandbox moves to its own site (S9).
