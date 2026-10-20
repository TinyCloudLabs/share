# Apps catalog

`/apps/` lists TinyCloud apps and shows, for each, what it can read and change.
The page is static: it has no SDK, no sign-in, and requests only this origin's
own files. Install is not available yet; the button is disabled.

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
- `name`, `description` and `app_id` repeat the bundle's `manifest.json`; the test checks they agree.

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
node scripts/vendor-app.mjs <git-url>@<tag> [--path <dir>] [--publisher <name>] [--publisher-did <did>]
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

`npm run test:e2e:apps-page` builds the site and checks the page in Chromium at 390 and
1440 px, light and dark, with axe (WCAG 2.x AA), the production headers, and
screenshots (`APPS_SCREENSHOT_DIR`).

## Provenance

The only vendored app is `examples/sqlite-app` from `TinyCloudLabs/tinycloud-app-kit`
at commit `5059c5b`. That repository is public and has no LICENSE file. Other apps
(for example the TinyHealth and TinyRecipes forks) are not vendored until their
licensing allows it.
