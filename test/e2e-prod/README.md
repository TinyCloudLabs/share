# Live-production browser acceptance harness

Everything else in `test/` runs in jsdom or against a local hermetic stack. This
directory drives **the deployed site** — `https://share.tinycloud.xyz`, a real
OpenKey passkey sign-in, the real registry, the real Node
(`tee.node.tinycloud.xyz`) — in a real Chromium, and reads a real mailbox.

It is deliberately **not** wired into `npm test`. It creates real shares and
sends real mail; run it on purpose.

For the same reason it is **excluded from the root `tsconfig.json`**: the
`playwright` dependency below is installed by `npm install` *in this
directory*, never by the repository's `npm ci`, so CI cannot type-check it.
It carries its own `tsconfig.json` at the root config's strictness — run
`npm run typecheck` here when you change `stage1b-viewer.ts` or a `lib/`
signature.

## Setup

```bash
cd test/e2e-prod
npm install
npx playwright install chromium   # if you have no Chromium yet
npm run typecheck                 # not covered by the repo's merge gate
```

## What to run

| Command | What it proves |
|---|---|
| `npm run trust-bundle` | Static checks on the deployed `config.json`: the SDK's `openCredentialsAudience` predicates, `nodeInvitationKid` scoping, key shapes. No browser. |
| `npm run stage1` | **Bearer / link-only, end to end through the composer UI.** Sign in, create a share, read the exact bytes back in a clean context. |
| `../../node_modules/.bin/tsx stage1b-viewer.ts` | The **viewer half only**, with the share minted by `createBearerShare` directly. Use when the composer is unreachable — it isolates the registry + viewer from the sender. |
| `npm run stage2` | **Addressed / exact-email to a Mailinator inbox.** Compose, send, read the inbox, follow the link, confirm, read the bytes. |

Useful env vars: `HEADED=1` (watch it), `BROWSER_CHANNEL=chrome` (real Chrome
instead of bundled Chromium), `FRESH_ACCOUNT=1` (register a new OpenKey account
instead of reusing `.account.json`), `TRACE_DEEP=1` (narrate every fetch,
postMessage, WebCrypto call and Worker — for localising hangs),
`SHARE_ORIGIN=…` (point at a different deployment).

Each run writes to `runs/<stage>-<timestamp>/`: `run.log`, `results.json`, the
downloaded bytes, the rendered document text, screenshots, and — for stage 2 —
redacted `network.json`, `delivery-authorization.json`, `invitation-email.txt`
and `recipient.txt`. Session cookies are never written; stage 1 records only
cookie names and local-storage key names in `sender-storage.redacted.json`.
OTP values, invitation bodies, bearer fragments, authorization headers, JWKs,
and other credential material are redacted before structured output is saved.

## Mailbox

`lib/mailinator.mjs` reads Mailinator's unauthenticated public-inbox API. It is
used for two things: the OTP that registers a fresh OpenKey account, and the
share invitation itself.

**Mailinator addresses only.** `stage2-addressed.mjs` refuses to start if the
recipient it generated is not `@mailinator.com`. Never point this harness at a
person.

The public API returns intermittent 500s; `getJson` tries `api.mailinator.com`
then `www.mailinator.com` before giving up on a poll.

## Passkeys

`lib/openkey.mjs` is the `openkey-passkey-test` skill's approach — a CDP
virtual WebAuthn authenticator (`WebAuthn.addVirtualAuthenticator`), so the
passkey gate runs with no Touch ID prompt. The captured credential is persisted
to `.account.json` (gitignored: it holds an exportable private key) and
re-installed with `WebAuthn.addCredential` on later runs, with `signCount`
bumped to wall-clock seconds — OpenKey rejects a stale counter.

Copy drifts. As of 2026-07 registration is "Create a passkey" (was "Register
Passkey") and the embed's chooser is "Use a passkey instead". `signInToShare`
matches both spellings where it can.

## Things a run has to click that a script would not guess

**The space-creation modal.** `TinyCloudWeb` always installs
`ModalSpaceCreationHandler`, which takes precedence over `autoCreateSpace: true`
(`web-sdk/src/modules/tcw.ts:413`, `NodeUserAuthorization.ts:760`). When the
Node's `POST /delegate` comes back `200` with the primary space in `skipped`,
`NodeUserAuthorization.ts:792` awaits `confirmSpaceCreation`, whose promise is
resolved only by a DOM click, with no timeout
(`WebSpaceCreationHandler.ts:33-45`). The modal is a shadow-DOM custom element
(`<tinycloud-space-modal>`), so nothing in the light DOM shows it is there and
the sign-in appears to hang forever at "Connecting to your encrypted
TinyCloud…". `signInToShare` finds it and clicks
`shadowRoot [data-action="create"]`, which is what a user would do.

**"Send by email…".** An addressed share does not mail anything when it is
created. The result screen offers `Send by email…`; only that click runs
`authorizeShareDelivery` and `POST {credentialsOrigin}/share/v2`.

**The share URL is never in the DOM.** By design (§6.3, TC-297/TC-334): the
composer hands it to `navigator.clipboard.writeText` and nothing else. The
harness installs an init script that records clipboard writes instead of
granting a clipboard permission, because granting one would change which branch
of `copyWithFallback` runs. For the clipboard-denied path, the tap rejects and
`document.execCommand` is forced to return `false`, driving the composer into
`armManualCopy`; the delivered value is then observed from a bubble-phase `copy`
listener, after the app's own capture-phase handler has substituted it.

**Markdown renders inside a sandboxed iframe.** `src/viewer/preview-frame.ts`
puts the document in a scriptless `sandbox=""` frame, so the top document's
`innerText` never contains it. Assert across `page.frames()`.
