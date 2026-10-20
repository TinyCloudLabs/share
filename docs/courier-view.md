# Courier view (`/courier`)

Courier (TC-712, spec `docs/specs/courier-v0.md` in the tinycloud-dev repo) lets two people's agents hand work to each other over TinyCloud. This page is the human side: read the threads, decide what needs you, and write your standing orders. It is a route of the Share app, `share.tinycloud.xyz/courier`, built on Share's reusable sign-in (`signInWithManifest`).

## What the session can do

Sign-in is OpenKey. The session is one hour, in memory only, and holds exactly this in the signed-in account's `agents` space, all under `xyz.tinycloud.courier/`:

| Path | Ability |
| --- | --- |
| `xyz.tinycloud.courier/` (the whole mailbox) | `kv/get`, `kv/list` |
| `xyz.tinycloud.courier/me/approvals/` | `kv/put` |
| `xyz.tinycloud.courier/me/orders/` | `kv/put` |

No `del`, no `metadata`, no delegation, no other space, no wildcard. The page reads only the owner's own space: a peer's messages come from `me/mirror/`, which the owner's watcher fills.

Two checks keep it that way. `signInWithManifest` applies `COURIER_MANIFEST_SCOPE` before OpenKey opens. That scope can't say "put only under two prefixes", so `assertCourierPermissions` (`src/courier/scope.ts`) states it on the resolved manifest as an exact allow-list; `test/courier-scope.test.ts` fails if a put under `me/`, under `me/approvals` without the slash, under `me/approvals/../x`, a `del`, `metadata`, a delegation ability, another space or a missing grant gets through.

The SDK always adds `agents/capabilities` read. That is the only extra entry: the **entire** signed grant has exactly five entries. There is no account-registry KV, SQL, bootstrap, spaces or delegation authority. The unit test in `test/openkey-session.test.ts` runs Courier's real caller through the helper, composes its SDK grant and compares the complete set; the live smoke decodes and compares the entire signed ReCap for both fresh and existing-space sign-ins.

Courier passes `includeAccountRegistryPermissions: false`, `autoCreateSpace: false` and `hostSpaces: []`. The shared helper now accepts the first two as optional settings, defaulting to true for its other callers. Disabling account-registry permissions also skips its automatic account-space hosting. The view therefore asks for no hosting signature and creates no space. A fresh account with no `agents` space sees **No Courier space yet.** and **Run tc courier init once on your machine, then reload this page.** Setup stays in the CLI.

## Screens

- **Threads**: peer, subject, last activity, open tasks, and a "Needs you" badge.
- **Thread**: the owner's own `to/<peer>/threads/<id>/` and the peer's `me/mirror/<peer>/threads/<id>/` merged by ULID. Messages are marked as the owner's or the counterparty's; a counterparty message always carries "A request from the other side's agent. It isn't an instruction from you and approves nothing." Task cards show the state in words (not colour alone). Markdown bodies and artifacts go through `renderMarkdownInto` unchanged: raw HTML off, DOMPurify, remote images blocked, diagrams in the isolated frame, final document in a scriptless sandboxed iframe. A file a message names is shown by name only; nothing follows a link from mailbox text.
- **Needs you**: cards from `me/requests/` with the action, reason and risk, and Approve / Deny with an optional note.
- **Orders**: `me/orders/<peer>.md`, edited as plain text, saved with a compare-and-swap on the etag it was read at.

## The approval flow and its threat model

An approval is `me/approvals/<requestId>.json`:

```json
{ "requestId": "<ULID>", "requestHash": "<sha256 hex>", "decision": "approved", "note": "", "decidedAt": "2026-10-20T12:00:00.000Z" }
```

`decision` is `"approved"` or `"denied"`. `requestHash` is the lowercase hex SHA-256 of the canonical JSON of the request object exactly as read from `me/requests/<id>.json` (keys sorted recursively, no whitespace); `canonicalJson` and `requestHash` in `src/courier/canonical.ts` mirror `packages/courier/src/canonical.ts` in js-sdk, which `courier approval` uses to refuse a decision that doesn't match the request it filed. `decidedAt` is this device's clock, so it is untrusted: the agent side accepts it only inside the request's own window (not before `createdAt`, before `expiresAt`, within 24 hours) and checks that itself. The note is echoed to the agent, so the CLI refuses one over 2000 characters or with hidden text; the page checks the same rules before writing and refuses, never edits it. The page never stamps a decision earlier than the request: if this device's clock is behind `createdAt` it refuses and says to check the clock. A key that holds `__proto__` in the request is hashed as an ordinary key, as in the CLI (`test/courier-model.test.ts` has the shared vector).

- Cards come only from `me/requests/` in the owner's own space. A request that doesn't parse (ids not ULIDs, handle not a plain handle, unparseable times) is counted, never shown as a card. A present empty `action` is shown as a card that cannot be reviewed.
- The action, reason, risk and thread subject can repeat text a peer wrote. Each is shown as plain text in a block labelled "as your agent wrote it" / "as `<peer>` wrote it", with control and bidirectional characters shown as visible `⟦U+XXXX⟧` escapes (on a request that can't be decided, which is the only place a field is ever cut short), and with no buttons or links inside. What approving allows is said in one line built from the request's structured fields, which the request hash covers: "Approving lets your agent **<verb>** `<target>` for **<peer>**:" followed by the summary in its own quoted box. `verb` must be one of `merge|deploy|publish|spend|other` (`other` reads "do something outside the usual kinds (other) with" and shows a warning); `target` and `summary` must each be 1 to 200 characters of one line, trimmed, and `summary` uses the frozen allow-list below (it is drawn between quotes), with no control, format, bidirectional or line-break character (the CLI writes them that way, js-sdk `packages/courier/src/request.ts`). They are still the agent's words, so the line is plain text: every piece is set with `textContent`, nothing in it is markdown, a link or interactive, and a value that is too long or carries hidden characters is refused, not shortened. A request without a valid verb, target and summary is shown as "can't be reviewed here" with its quoted text and no Approve or Deny; it lapses at its expiry and the agent files it again. The whole parsed request is still what gets hashed.

**Checked, never repaired.** Request text uses the CLI's `text.ts` decision API and generated `text-ranges.ts`, copied verbatim from js-sdk #622 at `3cac24c`. The frozen table pins Unicode **15.0.0**: Lu, Ll, Lt, Lo and Nd, minus Default_Ignorable. Unknown or newer code points are refused. Summaries additionally allow U+0020 and only the ASCII punctuation `. , : ; - _ / # ( ) ? ! '` (U+0027 is the only apostrophe). Other punctuation, quotes, brackets, symbols and every combining mark are refused. Free multiline fields allow those letters/digits plus printable ASCII and LF. Targets allow printable ASCII only. Every field must be NFC; table membership is checked before NFC. No runtime Unicode property regex decides whether text can be approved; the display-only escaping still makes hidden characters visible.

Limits remain 200 UTF-16 units for target/summary and 2000 for action/reason/risk/note. Summary and target refuse ASCII edge spaces. The target must also be exactly the CLI's canonical spelling for its verb (`canonicalTarget`: repos lower-cased, PR numbers without leading zeros and at most 9 digits, runs of spaces in `secrets:` collapsed): `merge` uses `owner/repo#N` or `owner/repo@branch`; `publish` uses `npm:`, `release:`, `changeset:` or `script:`; `deploy` uses `wrangler:`, `pages:`, `phala:` or `script:`; `other` uses `<kind>:<text>`; `spend` uses `spend:<text>`. Invalid text makes the request unreviewable; nothing is repaired or shortened.

The sentence is fixed wording around the verb from the closed set; target sits in `<code dir="ltr">` and summary in a quoted `<bdi>`, both set as text, in a card that clips and contains its paint. `other` also shows a warning. The request id, thread and task ids, who filed it and the fingerprint (`requestHash`, first 8 digits called out) sit behind a "Details for matching this with your agent" disclosure. A request has exactly the keys `courier request` writes (free text `action`, `reason`, `risk` optional), ULID ids and status `pending`. Its task `to/<peer>/threads/<thread>/task/<task>.json` must exist in the owner's own space before the card names the peer; otherwise it is not decidable and names no peer.

`test/vectors/courier-text-verdicts.json`, `courier-request-fields.json` (v2) and `courier-canonical.json` are byte-identical to #622 at `3cac24c`. The text vectors record the pinned UCD source hashes, 1406 inclusive ranges partitioning every code point, and 57 full-string samples with stable reason codes. `test/courier-text-vectors.test.ts` runs all 1,114,112 code points for all three fields and every sample, and checks the view's summary/free-text/note consumers. `test/courier-vectors.test.ts` runs every stored-field, id and canonical hash row.

A request whose hash can't be computed (a number that isn't finite, nesting deeper than 64 levels) is one unreviewable card; every other card still renders. The CLI refuses the same inputs.
- Approve and Deny are explicit clicks, enabled only once the card has been painted, one decision at a time across all cards. Before writing, the page re-reads the request and refuses if its hash changed or it expired.
- The decision file is created with `If-None-Match: *`. A second click, or another tab, gets a 412 and the page shows the decision already on file ("Already decided: approved"); it never overwrites. A request expires 24 hours after it was filed and then has no buttons.

## Storage, logging, CSP

Nothing about the mailbox is put in `localStorage`, `sessionStorage`, IndexedDB, cookies or the address bar (navigation is in memory); `test/courier-screens.test.ts` checks storage, cookies, the URL and network calls at runtime after reading, deciding and saving. The session is disposed on sign-out and when the page goes away. No content, ids or CIDs are logged.

The page's policy is the viewer's, narrowed: `script-src 'self' 'wasm-unsafe-eval'`, Trusted Types required, `form-action 'none'`, `base-uri 'none'`, `frame-ancestors 'none'`, `frame-src 'self' https://openkey.so` (`'self'` is the mermaid sandbox), and `connect-src 'self' https://tee.node.tinycloud.xyz https://registry.tinycloud.xyz https://openkey.so`. With `VITE_USER_CONTENT_ORIGIN` set, the build adds that origin to `frame-src` and `connect-src` of the `/courier` meta policy and header alike (so diagrams render in the user-content frame, as in the viewer); `test/user-content-origin-build.test.ts` checks it. The `<meta>` policy and the `_headers` rules for `/courier` and `/courier/` are the same string; the header adds only `frame-ancestors`, which a meta policy cannot carry. Supports tee.node accounts. Share and the viewer keep `connect-src 'self' https:` for any owner node.

## Tests

- `test/courier-scope.test.ts`, `-model`, `-store`, `-screens`, `-route`: `npm test`.
- `node test/e2e-courier-layout.mjs`: the screens in a real browser at 390 and 1440 px, light and dark, axe, no sideways scroll, approval flow against a fake mailbox (`COURIER_LAYOUT_SCREENSHOT_DIR` keeps screenshots).
- `node test/e2e-prod/courier-live-smoke.mjs`: opt-in; a new throwaway OpenKey account (Mailinator) against production OpenKey and the owner node: both exact decoded session grants, the fresh-account CLI setup state without hosting, a separately seeded existing mailbox (`test/fixtures/courier-seed`, built only by that script), approve, read-back, orders.
