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

The SDK adds the account-registry permissions to every sign-in (`signInWithManifest` lists them): get/put/list on `account/applications/` and `account/spaces/`, the bootstrap flag, read/write/schema on the account database and the delegation list. They are not removable. The live smoke decodes the signed request and asserts the `agents` part is exactly the table above and that nothing else on the account can be written beyond those SDK entries.

The page never hosts a space. If the `agents` space doesn't exist it says so and how to set it up.

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

`decision` is `"approved"` or `"denied"`. `requestHash` is the lowercase hex SHA-256 of the canonical JSON of the request object exactly as read from `me/requests/<id>.json` (keys sorted recursively, no whitespace); `canonicalJson` and `requestHash` in `src/courier/canonical.ts` mirror `packages/courier/src/canonical.ts` in js-sdk, which `courier approval` uses to refuse a decision that doesn't match the request it filed. `decidedAt` is this device's clock and is informational only; the agent side checks age and expiry itself.

- Cards come only from `me/requests/` in the owner's own space. A request that doesn't parse (ids not ULIDs, handle not a plain handle, unparseable times, empty action) is counted, never shown as a card.
- The action, reason, risk and thread subject can repeat text a peer wrote. Each is shown as plain text in a block labelled "as your agent wrote it" / "as `<peer>` wrote it", capped in length, with control and bidirectional characters shown as visible `⟦U+XXXX⟧` escapes, and with no buttons or links inside. The line saying what approving allows is built from structured fields only (the peer handle and the task id), never from those texts.
- Approve and Deny are explicit clicks, enabled only once the card has been painted, one decision at a time across all cards. Before writing, the page re-reads the request and refuses if its hash changed or it expired.
- The decision file is created with `If-None-Match: *`. A second click, or another tab, gets a 412 and the page shows the decision already on file ("Already decided: approved"); it never overwrites. A request expires 24 hours after it was filed and then has no buttons.

## Storage, logging, CSP

Nothing about the mailbox is put in `localStorage`, `sessionStorage`, IndexedDB, cookies or the address bar (navigation is in memory); `test/courier-route.test.ts` scans `src/courier` for those sinks, `innerHTML`, `console`, and any network call of its own. The session is disposed on sign-out and when the page goes away. No content, ids or CIDs are logged.

The page's policy is the viewer's, narrowed: `script-src 'self' 'wasm-unsafe-eval'`, Trusted Types required, `form-action 'none'`, `base-uri 'none'`, `frame-ancestors 'none'`, `frame-src 'self' https://openkey.so` (`'self'` is the mermaid sandbox), and `connect-src 'self' https://tee.node.tinycloud.xyz https://registry.tinycloud.xyz https://openkey.so`. The `<meta>` policy and the `_headers` rules for `/courier` and `/courier/` are the same string; the header adds only `frame-ancestors`, which a meta policy cannot carry. `/courier` therefore works for accounts on the `tee.node` owner node only; Share and the viewer keep `connect-src 'self' https:` for any owner node.

## Tests

- `test/courier-scope.test.ts`, `-model`, `-store`, `-screens`, `-route`: `npm test`.
- `node test/e2e-courier-layout.mjs`: the screens in a real browser at 390 and 1440 px, light and dark, axe, no sideways scroll, approval flow against a fake mailbox (`COURIER_LAYOUT_SCREENSHOT_DIR` keeps screenshots).
- `node test/e2e-prod/courier-live-smoke.mjs`: opt-in; a new throwaway OpenKey account (Mailinator) against production OpenKey and the owner node: the decoded session request, a seeded mailbox (`test/fixtures/courier-seed`, built only by that script), approve, read-back, orders.
