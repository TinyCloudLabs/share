# Apps catalog

`/apps/` lists TinyCloud apps and shows, for each, what it can read and change, and installs an app's
files into the person's own TinyCloud. Until a person clicks Install the page has no SDK, no sign-in,
and requests only this origin's own files.

## Files

| Path | What |
| --- | --- |
| `apps/catalog.json` | The catalog, `schema: tinycloud.share.apps-catalog/v1`. Compiled into the page. |
| `public/apps/b/<digest>/` | One vendored bundle per entry, served as `/apps/b/<digest>/`. Committed. |
| `scripts/vendor-app.mjs` | Dev-time: copies a bundle from a git tag and pins it in the catalog. |
| `scripts/apps-catalog.mjs` | Digest and verification logic shared by the script and the test. |
| `apps/index.html`, `src/apps/` | The page. |

## Entry

```json
{
  "app_id": "com.example.notes",
  "name": "Notes",
  "description": "…",
  "publisher": { "name": "TinyCloud", "did": "optional" },
  "source": { "repo": "https://github.com/…", "tag": "v1.0.0", "commit": "<40 hex>" },
  "manifest": { "path": "manifest.json", "sha256": "<hex>" },
  "bundle": {
    "root": "/apps/b/<digest>/",
    "files": [{ "path": "manifest.json", "sha256": "<hex>", "size": 123 }],
    "digest": "<hex>"
  },
  "knowledge": { "root": "/apps/b/<digest>/knowledge/", "digest": "<hex>" }
}
```

- `source.tag` is `null` when the entry pins a bare commit (the source repo has no tag).
- `knowledge` is `null` when the bundle has no `knowledge/` folder.
- `name`, `description` and `app_id` repeat the bundle's `manifest.json`; the test checks they agree, and the installer refuses a bundle whose manifest differs.
- `sample` is `true` for sample apps and absent otherwise; `release` is present when the bundle ships a `release.json` (see "Sample apps"); `disabled` and `disabledReason` are the optional kill switch (see "Kill switch").

## Kill switch

An entry can be switched off without touching its bundle:

```json
{ "app_id": "…", "disabled": true, "disabledReason": "Pulled while a problem is looked into." }
```

- `disabled` is `true` or absent; `disabledReason` (1 to 280 characters) is required with it and allowed only with it. `verifyCatalog` checks this.
- The flag lives in the entry, not in the bundle, so no digest changes when it flips and the integrity checks stay valid. `vendor-app.mjs` keeps it when an app is updated.
- The page shows the card with "Temporarily unavailable" and the reason (as text), disables Install on the card and in the details sheet, and a forced click opens only a sheet that says so. The installer refuses a disabled entry before it fetches a file or makes the sign-in ports (`InstallError` reason `disabled`).
- It takes effect when the site is deployed **and the page is reloaded**: the flag is compiled into the page's JavaScript (the headers are `no-store`, so a reload fetches the new build), and a tab that is already open keeps the catalog it loaded. Within one page load the card, the sheet, the flight and `runInstall` all refuse. The page cuts a `disabledReason` over `MAX_DISABLED_REASON_CHARS` (280) with a "…"; the catalog check refuses it.
- The runner (T5b) uses the same helpers from `src/apps/catalog.ts`: `availabilityOf(entry)` and `assertAvailable(entry)` (throws `EntryDisabledError`), so one flag stops install and open.

## Digest

A bundle is a set of files addressed by relative POSIX paths.

1. Sort the files by path, comparing UTF-16 code units (so `B.md` sorts before `a.md`).
2. Write one line per file: `<sha256 hex> <size in bytes> <path>\n`.
3. `digest` is the lowercase hex sha256 of the UTF-8 bytes of that text.

`bundle.digest` covers every file. `knowledge.digest` covers the files under
`knowledge/`, with paths relative to that folder. `bundle.root` is
`/apps/b/<bundle.digest>/`. An installer recomputes the same digests from the
bytes it fetched before it writes anything.

## Adding or updating an app

```sh
node scripts/vendor-app.mjs <git-url>@<tag> [--path <dir>] [--sample] [--publisher <name>] [--publisher-did <did>]
```

- `<tag>` is a tag name or a full 40-hex commit id. Branches are refused because they move.
- `--path` is the folder in the repo that holds the bundle (default `tinycloud/app`).
- `--publisher` is required for a new app and kept for an existing one.
- Updating an app replaces its entry and deletes the bundle folder it supersedes.
- The script runs on a developer machine and its output is committed. The build and the site fetch nothing.

`npm test` recomputes every digest and file hash (`test/apps-catalog.test.ts`).
A changed, added or removed file, or a catalog edited to disagree with its
files, fails it.

## What the detail sheet shows

The sheet fetches the entry's manifest from `bundle.root`, checks it against
`manifest.sha256`, and shows nothing from it if the bytes differ. Items come
from the manifest's own `description`s and are rendered with `textContent`.

The lists mirror what the SDK's `resolveManifest` would sign, and only that
(`src/apps/access.ts`):

- `permissions[]`, with the app's path prefix applied unless `skipPrefix`, and each entry's `space`;
- `secrets{}` (an object keyed by secret name), as vault grants in the `secrets` space;
- the default tier: a manifest that does not set `defaults: false` also gets the SDK's standard grant for its own folder (`"admin"` adds SQL schema changes, `"all"` adds DuckDB);
- the one addition the SDK makes itself: `capabilities/read` in each space used. (A public-space grant is made only when a key-value grant is handed to another DID, not at sign-in, so it is not listed.)

The kit's descriptive `resources.*` blocks grant nothing in the SDK, so they are not listed.

`npm run test:e2e:apps-page` builds the site and checks the page and the install sheets in Chromium
at 390 and 1440 px, light and dark, with axe (WCAG 2.x AA), the production headers, and
screenshots (`APPS_SCREENSHOT_DIR`).

## Install

"Install" on a card or in the details sheet opens a pre-consent sheet, then runs the install in
`src/apps/install*.ts`. Nothing is signed or written until the person clicks Continue; the SDK and
OpenKey load only then.

1. **Verify, before OpenKey.** Every file of the bundle is fetched from the entry's own
   `/apps/b/<digest>/` (same origin, no redirects) and must match the catalog's sha256 and size. The
   entry's own file list must hash to its digest, and its paths must pass the install rule
   (`src/apps/bundle.ts`, mirrored by `installPathProblem` in `scripts/apps-catalog.mjs`):
   relative, ASCII `[A-Za-z0-9._-]` segments with no leading dot (so no hidden folder, `..`,
   absolute, backslash or control-character path), at most 8 folders and 128 characters, never
   `install.json`, no file below a `dev/`, `tests/`, `test/`, `scripts/` or `node_modules/` folder, and
   no two paths that differ only by case. One bad file refuses the whole install: nothing is
   written and OpenKey is not opened.
2. **One sign-in** (`signInWithManifest`; a brand-new account is also asked to host its spaces, which the gate measured as 4 OpenKey signatures, and an existing account as 1) with the *installer manifest* (`src/apps/install-plan.ts`).
   It takes the app's id, name and description from the verified manifest and nothing else:
   `defaults: false`, no `secrets`, no `did`, no public space, and exactly two grants in the
   `applications` space: `put` on `<app_id>/app/` and `put` on `<app_id>/knowledge/`. The SDK adds the
   account registry's permissions (`includeAccountRegistryPermissions`) and `capabilities/read`. The
   app's own runtime grants (its SQL, key-value prefixes, reads of another app) are **not** part of
   this sign-in: the app asks for them with its own sign-in when it is opened. Just before OpenKey
   opens, the SDK's `composeManifestRequest` of the installer manifest is compared with the list the
   sheet shows, and the install stops on any difference or any delegation target.
3. **Create-only writes** into `<app_id>/app/<path>` (and `<app_id>/knowledge/<path>` for
   `knowledge/**`), with `If-None-Match: *`. A file that already exists (a `412`) is the person's
   copy and is kept, so a hand-edited `knowledge/app.md` survives a re-install.
4. **`<app_id>/app/install.json`** (`{ source, digest, installed_at }`) is written last, create-only.
   "Installed" is only ever said about a bundle that is entirely in place. If a write fails, what
   was saved stays, the sheet lists it, and Try again resumes: it keeps those files and writes the
   rest. A re-install of a finished install writes nothing and says "Already installed: your copy
   is kept."
5. **Apps list.** The SDK records the app in the account's apps list in the background right after
   sign-in; the install waits for it to show (and registers it itself once if it does not). The
   record is the installer's: the app id and a manifest hash (the web SDK stores `manifests: []`),
   never the app's own grants. **A half-finished install shows in the apps list**, because the SDK
   records the app at sign-in, before any file is written: `install.json`, written last, is the only
   marker of a complete install (the runner, agents and the knowledge docs must use it, not the list).
   For the same reason the record cannot be used to compare grants later: its hash is the hash of an
   empty manifest list, the same for every app. The runner (T5b) caps an app's grants against the
   catalog manifest instead.

No standing delegation is created: the session is in memory for 15 minutes at most and is disposed when the install ends; opening an
app later asks for a fresh sign-in. Opening an installed app (`/apps/run#<app_id>`) is the next slice;
until it lands the sheet says so and offers no link.

One install runs at a time per app (`src/apps/install-flight.ts`): a second click joins the running
install and starts no second sign-in. A catalog update between a failed install and its retry would
fill the missing files from the newer bundle while `install.json` records the newer digest; updates
are a separate feature.

`test/apps-install*.test.ts` cover verification, create-only handling (through the real port with a
fake client: every put carries `ifNoneMatch`, only a precondition failure means "kept"), the
sheet-versus-SDK check before OpenKey opens, the session length (one constant, `INSTALL_EXPIRY_MS`; the
sheet's "15 minutes" is derived from it), disposal, resume, the double click and the sheet. `node test/e2e-prod/install-gate.mjs` installs the Health Log sample on the hermetic
native stack in a real browser (see that file's header).

## Sample apps

An entry marked `"sample": true` is a sample: its install sheet says "Sample app: use throwaway data
only." and its card shows a Sample badge. Any app that writes SQL (the default grant included) also
says "This app can change or delete its own tables.", and a grant on another app's database is listed
as "This app can read <app>'s database (whole database)." (`src/apps/consent.ts`, from the same
`summarizeAccess` the lists use.)

Those sentences cover every reach a grant can have in a manifest the page accepts, from its resolved
path (`path` on each list item, as the SDK resolves it): its own folder, the whole space (an empty
path), another app's folder, a root-level key or database that no folder holds (`skipPrefix` with a
bare name), any space other than `applications`, the vault shorthand (`tinycloud.vault`, key-value
under `vault/`), named secrets (`vault/secrets/<NAME>` in the `secrets` space), and encryption
grants. An encryption grant is a network id, not a folder, and the node checks only that id, so
`decrypt` is not limited to what the app stored: the sheet says "This app can decrypt anything
encrypted to your TinyCloud encryption network (...), including data it did not store." (and
"...create or revoke encryption networks" for the other two actions). Text from a manifest that a
sentence repeats is cut at 120 characters with a "…". An empty path is shown as "everything in the
<space> space". Examples: "This app can change or delete any file in your applications space,
including other apps' files.", "...every file in your default space.", "...the database healthlog,
which is not inside its own folder."

**Described, with no sentence of their own** (the lists already say them): key-value access in the
app's own folder, reads of its own SQL or DuckDB databases, and the read of each space's permission list
that the SDK adds itself (marked "added automatically"). Every other change or read gets a sentence.

**Refused, not described**, because the SDK resolves them in a way the lists do not mirror:
- a manifest `did` (it hands everything the app is granted to that key);
- a `prefix` that is not text, or a `space` that is not text or is blank (the SDK uses them as written, where the page would read them as "not given"), in the manifest or in a permission;
- an explicit `tinycloud.capabilities` permission (the SDK adds that read per space itself, so a hand-written one is a second row for the same thing).

`unsupportedManifest` (`src/apps/access.ts`) refuses them before OpenKey opens (`bundle.ts`), the
sheet says so and keeps Continue off, and `verifyCatalog` refuses a catalog manifest with one. No
catalog app has any of them. `test/apps-consent.test.ts` checks each shape, that the lists equal what
the SDK's `resolveManifest` resolves for every shape (nothing skipped), that every grant outside the
own folder has a sentence, and that each refused shape is one the SDK really resolves differently.

When a bundle folder has a `release.json` (`tinycloud.app-release/v1`, as the kit's samples do),
`vendor-app.mjs` copies ONLY the files it lists plus `release.json`, checks each against the sha256
the release declares and the release's own digest, and records `release: { version, digest }` in the
entry. That digest is the kit's scheme (sha256 of the path-sorted `<path> <sha256>` lines joined by
`\n`); the catalog digest above is the one an installer verifies, and the test checks both.
`--sample` sets the flag and later updates keep it.

## Provenance

| App | Source | Pinned at |
| --- | --- | --- |
| `com.example.notes` | `TinyCloudLabs/tinycloud-app-kit` `examples/sqlite-app` | commit `5059c5b` |
| `xyz.tinycloud.sample.healthlog` (sample) | same repository, `examples/sample-healthlog` | commit `d8739346a833d0ac5941fcfc51e378ba0281ccb3` (the repository has no tags) |
| `xyz.tinycloud.sample.recipes` (sample) | same repository, `examples/sample-recipes` | commit `d8739346a833d0ac5941fcfc51e378ba0281ccb3` |

That repository is public and has no LICENSE file. Other apps (for example the TinyHealth and
TinyRecipes forks) are not vendored until their licensing allows it.
