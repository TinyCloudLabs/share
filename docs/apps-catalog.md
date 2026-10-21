# Apps catalog

`/apps/` lists TinyCloud apps and shows, for each, what it can read and change. Opening an app saves its files into the person's own TinyCloud when they are not there yet, and the app runs at `/apps/run#<app_id>` ([tiny-app-runner.md](tiny-app-runner.md)). Until a person opens an app, the page has no SDK and no sign-in, and requests only this origin's own files.

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
- `name`, `description` and `app_id` repeat the bundle's `manifest.json`; the test checks they agree, and opening refuses a bundle whose manifest differs.
- `sample` is `true` for sample apps and absent otherwise; `release` is present when the bundle ships a `release.json` (see "Sample apps"); `disabled` and `disabledReason` are the optional kill switch (see "Kill switch").

## Kill switch

An entry can be switched off without touching its bundle:

```json
{ "app_id": "…", "disabled": true, "disabledReason": "Pulled while a problem is looked into." }
```

- `disabled` is `true` or absent; `disabledReason` (1 to 280 characters) is required with it and allowed only with it. `verifyCatalog` checks this.
- The flag lives in the entry, not in the bundle, so no digest changes when it flips and the integrity checks stay valid. `vendor-app.mjs` keeps it when an app is updated.
- The page shows the card with "Temporarily unavailable" and the reason (as text). Open still links to the runner, which refuses the entry before any sign-in and shows the same reason; Details shows it too. The card has no Install action.
- It takes effect when the site is deployed **and the page is reloaded**: the flag is compiled into the page's JavaScript (the headers are `no-store`, so a reload fetches the new build), and a tab that is already open keeps the catalog it loaded. Within one page load the card, the details sheet and the runner all refuse. The page cuts a `disabledReason` over `MAX_DISABLED_REASON_CHARS` (280) with a "…"; the catalog check refuses it.
- The runner uses the same helpers from `src/apps/catalog.ts`: `availabilityOf(entry)` and `assertAvailable(entry)` (throws `EntryDisabledError`), so one flag stops opening.

## Digest

A bundle is a set of files addressed by relative POSIX paths.

1. Sort the files by path, comparing UTF-16 code units (so `B.md` sorts before `a.md`).
2. Write one line per file: `<sha256 hex> <size in bytes> <path>\n`.
3. `digest` is the lowercase hex sha256 of the UTF-8 bytes of that text.

`bundle.digest` covers every file. `knowledge.digest` covers the files under
`knowledge/`, with paths relative to that folder. `bundle.root` is
`/apps/b/<bundle.digest>/`. Opening an app recomputes the same digests from the
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

`npm run test:e2e:apps-page` builds the site and checks the page and the details sheets in Chromium
at 390 and 1440 px, light and dark, with axe (WCAG 2.x AA), the production headers, and
screenshots (`APPS_SCREENSHOT_DIR`).

## Opening an app saves it

Opening an app is the only way an app is added to a person's TinyCloud. The card's primary action is Open, which links to `/apps/run#<app_id>` ([tiny-app-runner.md](tiny-app-runner.md)); Details is the secondary action and opens the details sheet. Nothing is signed or written until the person clicks Continue on the runner's start screen. The SDK and OpenKey load only then.

The start screen shows the first-open disclosure before Continue (`src/apps/first-open.ts`; the details sheet shows the same list). It says that the app runs with its own sign-in, that its manifest lists what it can read and change, who publishes it, and that opening it saves its files when they are not in the person's TinyCloud yet. Direct links show it too.

Each open runs these steps in order (`openApp` in `src/apps/run.ts`):

1. **Refuse before any sign-in.** An unknown app, an entry switched off by the kill switch (`EntryDisabledError`, shown with its reason), or an entry without `app.jsx` is refused here, before OpenKey is contacted.
2. **Verify the bundle, every open.** Every file is fetched from the entry's own `/apps/b/<digest>/` (same origin, no redirects) and must match the catalog's sha256 and size; the file list must hash to the digest; and the paths must pass the install rule (`src/apps/bundle.ts`, mirrored by `installPathProblem` in `scripts/apps-catalog.mjs`). A failure refuses the open before OpenKey.
3. **First approval: one read session.** One OpenKey sign-in with a session for the app's folders, `<app_id>/app/` and `<app_id>/knowledge/`. It carries get, list and create-only `put` (`ifNoneMatch: "*"`) on `<app_id>/app/`, and create-only `put` on `<app_id>/knowledge/`. Every open therefore takes two approvals: this one and the runtime session.
4. **Save what is missing.** Each app file that is not in the person's TinyCloud is written create-only (`ifNoneMatch: "*"`), in catalog order. A file that is already there is kept as it is, and step 5 checks it before `install.json` is written. A file that appears between the read and its save stops the save ("saved files changed while opening"), and nothing more is written.
5. **Write `install.json` after the app files.** `<app_id>/app/install.json` (`{ source, digest, installed_at }`) is written only when no record is saved and the saved code files pass the same check as the open: every code file present, no extra file, each with the catalog's sha256 and size. A failure stops the save with "`<reason>`, so install.json was not written". `manifest.json` is not pinned here; it is capped at verification (step 6). Notes are written after `install.json`, with `knowledge/index.md` last. A folder with `install.json` and every app file counts as installed; notes missing afterwards are written by the next open. The apps list is not used for that.
6. **Verify the saved app.** The saved files are checked against the catalog version (`verifyStoredApp`), and the manifest is capped against the catalog manifest. A copy whose code files differ from the pins is refused on the "doesn't match the pinned version" screen, which offers Repair. A copy recorded for a digest that is not in the catalog is refused as not listed: the page cannot check or repair it, so it shows the steps to delete its files by hand. Nothing is upgraded silently.
7. **Second approval: the runtime session.** The read session ends before the app frame exists. A second OpenKey sign-in opens the runtime session, with grants capped to the catalog manifest at the installed digest (valid for one hour). The bridge allow-list comes only from the app's resolved manifest, never from the read session.

## Cancel, failure, and partial saves

While an open runs, the progress line shows the step, and a Cancel button sits beside it (Escape cancels too). Cancel stops the open before any further write or app start, and the screen says "Sign-in cancelled. Nothing was started." If the OpenKey window is still open after Cancel, it closes at the end of its request timeout. If the approval arrives after Cancel, the session is closed and nothing is written. Files saved before the cancel stay in place.

Every failure has a title and a plain sentence in the runner's result screen (`failureScreen` in `src/apps/run-view.ts`). A save that stops partway keeps the files already written. Opening the app again keeps them and writes the rest; `install.json` is written once the code files pass the pin check.

Repair (`src/apps/repair.ts`) replaces the app's saved code files with the catalog copy after a confirmation sheet. It takes one approval. The knowledge folder and `install.json` are left as they are.

`test/apps-open-install.test.ts` covers the open steps (verification before any sign-in, create-only writes, the order of `install.json`, cancel during the save, a saved listing that could not be read in full). `test/apps-runner-view.test.ts` and `test/apps-view.test.ts` cover the start screen, the result screens and the card actions. `test/e2e-apps-widget-layer.mjs` drives the real SDK against a stand-in OpenKey window at 390, 1100 and 1440 px and checks that nothing modal sits above the window, that a click reaches it, and that Cancel and Escape end the open. `test/e2e-prod/install-gate.mjs` and `test/e2e-prod/runner-gate.mjs` run the same flow against real OpenKey; they are run by QA, not in CI.


## Uninstall

"Uninstall" is on an app's details sheet. It removes the app's code, manifest, install record and agent knowledge notes, and keeps the app's data.

- **Confirm sheet.** It names the app and says what goes (the files under `<app_id>/app/` and `<app_id>/knowledge/`, including notes the person edited there) and what stays (SQL databases and prefs under `<app_id>/`, and files outside those folders). It lists the read of each hosted space's permissions that the SDK adds (applications and account), worded as on the install sheet. It asks the person to close the app's open tabs first. "Keep app" closes the sheet; nothing is signed or changed.
- **One sign-in** with the uninstaller identity (`tinycloud-share-uninstall`, `src/apps/uninstall-plan.ts`). Its ReCap is checked against the confirm sheet before OpenKey opens: the request grants `kv` list and delete on `<app_id>/app/` and `<app_id>/knowledge/`, and delete on the single key `applications/<app_id>` in the account space. Registry sync is not awaited.
- **Order.** `<app_id>/knowledge/index.md`, then `<app_id>/app/install.json`, then the rest of `app/` and `knowledge/` in sorted order, then the registry record last. A missing key counts as success, so a retry after an interruption finishes the job. An interrupted run leaves a partial install, which Uninstall can finish again.
- **Listing limit.** A listing that is still truncated after 200 pages of 500 keys stops the run before anything is deleted.
- **Keys outside the folders are ignored.** A listed key outside `<app_id>/app/` and `<app_id>/knowledge/` is skipped, not deleted, so a listing cannot widen the delete set. The delete plan applies the same filter, so no `del` is issued for such a key.
- **Registry failure is not fatal.** The files are already gone, so the sheet says "The app was removed; its entry in your account list couldn't be updated; try again." A retry removes only the registry entry.
- **Stopped before sign-in.** If the signed request does not match the confirm sheet, or would delegate to another identity, the run stops before OpenKey opens: "Couldn't start the uninstall. Nothing was changed. Try again."
- **Nothing listed.** If the app has no files left, the run only removes the registry entry and the sheet says there was nothing to remove.
- **Account app list.** The SDK's `applications.remove` treats a failed removal of the app's index row as success. After an uninstall, `applications.list()` no longer returns the app, but `applications.list({ preferIndex: true })` (and `tc account applications`) can still show it. The uninstall cannot report this.
- **Re-install** after an uninstall works, and the kept SQL and prefs are still there.

`test/apps-uninstall*.test.ts` cover the path guard (`isOwnedKey`, including `<app_id>2`, `..`, `%2e` and empty ids), the ignore rule for listed keys outside the folders, the delete order, pagination and the truncation limit, the confirm-sheet/ReCap match and the sheet's delete and read rows, the stop-before-sign-in copy, the nothing-to-remove copy, and the registry-failure retry. `test/e2e-prod/install-gate.mjs` (stage 6) and `runner-gate.mjs` (stage 8) run uninstall against the hermetic stack; see those files' headers.

## Sample apps

An entry marked `"sample": true` is a sample: its runner and its details sheet say "Sample app: use throwaway data only.", and its card shows a Sample badge. Any app that writes SQL (the default grant included) also
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

**Described, with no sentence of their own** (the lists already say them): any read inside the app's
own folder, key-value changes inside the app's own folder, and the read of each space's permission list
that the SDK adds itself (marked "added automatically"). Changes inside the own folder to anything
other than key-value (SQL, DuckDB and any other service) do get a sentence ("This app can change or
delete its own tables.", "...its own DuckDB data."), and so does every change or read outside the own
folder.

**Refused, not described**, because the SDK resolves them in a way the lists do not mirror:
- a manifest `did` (it hands everything the app is granted to that key);
- a `prefix` that is not text, or a `space` (in the manifest or in a permission) that is not text or has no visible character in it (the SDK uses them as written, where the page would read them as "not given" or show an invisible name);
- an invisible character, or any space other than U+0020, in a displayed space, path, service, prefix or secret name or scope. "Invisible" is one definition (`src/share/invisible-text.mjs`, shared with the sign-in labels): any Unicode control, format, surrogate, private-use, unassigned, line or paragraph separator character, any space separator other than U+0020, the Hangul, Khmer and Mongolian fillers, variation selectors and the combining grapheme joiner (U+200B, U+200C, U+2060 and U+0085 among them);
- an explicit `tinycloud.capabilities` (or `capabilities`) permission (the SDK adds that read per space itself, so a hand-written one is a second row for the same thing).

`unsupportedManifest` (`src/apps/manifest-support.mjs`, one function) is what the verified bundle fetch
(`bundle.ts`, before OpenKey opens), the details sheet (an alert, the app can't be opened) and `verifyCatalog` all call. No
catalog app is refused by it. `test/apps-consent.test.ts` checks each shape, that the lists equal what
the SDK's `resolveManifest` resolves for every shape (nothing skipped), that every grant outside the
own folder has a sentence, that each refused shape is one the SDK really resolves differently, and each
class of invisible character.

When a bundle folder has a `release.json` (`tinycloud.app-release/v1`, as the kit's samples do),
`vendor-app.mjs` copies ONLY the files it lists plus `release.json`, checks each against the sha256
the release declares and the release's own digest, and records `release: { version, digest }` in the
entry. That digest is the kit's scheme (sha256 of the path-sorted `<path> <sha256>` lines joined by
`\n`); the catalog digest above is the one opening an app verifies, and the test checks both.
`--sample` sets the flag and later updates keep it.

## Provenance

| App | Source | Pinned at |
| --- | --- | --- |
| `com.example.notes` | `TinyCloudLabs/tinycloud-app-kit` `examples/sqlite-app` | commit `5059c5b` |
| `xyz.tinycloud.sample.healthlog` (sample) | same repository, `examples/sample-healthlog` | commit `d8739346a833d0ac5941fcfc51e378ba0281ccb3` (the repository has no tags) |
| `xyz.tinycloud.sample.recipes` (sample) | same repository, `examples/sample-recipes` | commit `d8739346a833d0ac5941fcfc51e378ba0281ccb3` |

That repository is public and has no LICENSE file. Other apps (for example the TinyHealth and
TinyRecipes forks) are not vendored until their licensing allows it.

Details: TC-1422
