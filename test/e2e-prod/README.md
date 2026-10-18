# TC-500 production-origin gate

This directory is intentionally separate from the regular test command. The
gate creates real owner data and mails only a disposable `@mailinator.com`
recipient, so it must be explicitly enabled after the Node and OpenCredentials
production deployments are green.

`candidate-server.mjs` serves the current `dist/` over local TLS. A dedicated
Chrome instance maps only `share.tinycloud.xyz` to that local listener. The URL
and Origin the browser presents remain `https://share.tinycloud.xyz`; the
owner node, `witness.credentials.org`, and `registry.tinycloud.xyz` are never
proxied. It parses the candidate's copied `public/_headers` and applies the
same CSP, Trusted Types, sandbox, cache, referrer, and MIME-sniffing contract
as production. It refuses every Host other than `share.tinycloud.xyz` and has
no upstream fallback.

That last point is deliberate: the TC-500 Share application has no
same-origin auth, registry, blob, credential, or data-plane endpoint. Adding a
proxy to an obsolete `/share/*` or generic API route would hide a regression.

The final runner must capture, from one new recipient browser context:

- no OpenKey request before render;
- OpenCredentials `/v1/acquisitions`, Node Policy/v3, generic `/delegate`,
  and generic `/invoke` requests;
- ciphertext from the owner's KV only, before local decrypt/render; and
- exact non-UTF-8 input bytes plus the denial/revocation/tamper cases.

The gate cryptographically verifies the owner's signed Location Registry
record before launching Chrome and then requires the browser's Policy/v3,
`/delegate`, and `/invoke` traffic to use that same discovered Node origin.
Credential acquisition is pinned exactly to `https://witness.credentials.org`.
Browser message text and request bodies are never emitted: the report contains
only fixed route labels, origin bindings, counts, and the expected byte digest.

Run only with a disposable Mailinator inbox and an explicitly provisioned
owner account. Never point this at a real recipient or alter system DNS; use
Chrome's per-process host resolver rule and dispose of the browser profile and
temporary certificate after the run.

`recipient-gate.mjs` is the executable recipient half. It is deliberately
opt-in and requires the actual mailed invitation, its Mailinator OTP, and the
sender's original non-UTF-8 file. It verifies the downloaded local bytes and
the required OpenCredentials/Policy-v3/delegate/invoke trace, while refusing
OpenKey or legacy Share traffic. It does not create an invitation itself.

`joined-gate.mjs` is the hermetic release gate. It boots the released Node
v1.21.0 tree, the reviewed OpenCredentials candidate tree (8-digit mailbox codes), and the current
Location Registry tree, while serving only the candidate static Share build
at the production origin. It creates the sender share through the real browser
UI, captures mail through a loopback Resend-compatible sink, and opens the
invitation in a fresh browser context. Request interception changes only
transport: browser URLs, Origin headers, CSP, Trusted Types, policy audiences,
and signed discovery records retain their production values. The stack has no
Share API or Share registry.

After the browser journeys, the gate runs the agent-style sender: the `tc` CLI
publishes an exact-email share with `tc share publish <file> --to email:<addr>
--notify`, and a fresh browser context claims the mailed link and must download
the exact bytes. The CLI is preloaded with `cli-transport.mjs`, which keeps the
canonical origins and remaps only transport to the stack. It refuses every
other destination at three layers (fetch origins, DNS, and raw `net.Socket`
connects to non-loopback hosts, which covers IP literals and http/https/tls
clients), and the leg fails if the CLI tried one. `TC500_CLI_PACKAGE` names an
installed `@tinycloud/cli` package root. Its default,
`/tmp/tc500-cli/node_modules/@tinycloud/cli`, is not provisioned by anything:
install a CLI there first (`npm install --prefix /tmp/tc500-cli
@tinycloud/cli@<version>`) or point the variable at a built js-sdk
`packages/cli`. The gate is red for every published CLI up to and including
1.3.0-beta.7: those releases reject the Node's delivery receipt and never email
the recipient (TC-1424, fixed by TinyCloudLabs/js-sdk#581). It turns green once
a CLI containing that fix is used.

No CI workflow runs this gate; it is a manual release check.

The gate refuses dirty or non-reviewed dependency trees. Defaults are the
local stable worktrees listed in `native-stack.mjs`; explicit paths may be
provided with `TC500_NODE_WORKTREE`, `TC500_OPENCREDENTIALS_WORKTREE`, and
`TC500_REGISTRY_WORKTREE`. `TC500_NODE_COMMIT`, `TC500_OPENCREDENTIALS_COMMIT`,
and `TC500_REGISTRY_COMMIT` may name a reviewed candidate commit instead of the
stable pin; the worktree must still be clean and at exactly that commit, and
its tree digest is recorded in the artifact.

```bash
npm run test:e2e:native-joined
```

A run cannot hang the host. Every fixture process and every one-shot setup step
runs in its own process group, and the whole group is killed when a step times
out or finishes, when the gate exits, after a failed start, and on
SIGINT/SIGTERM, so build or script grandchildren cannot be orphaned. One-shot
steps time out (cargo and pnpm builds after `TC500_BUILD_TIMEOUT_MS`, default 30
minutes; the Share build after 10 minutes; other steps after 5 minutes).
Once the stack is up, the journey must finish within `TC500_JOURNEY_TIMEOUT_MS`
(default 15 minutes). A failed start names its step in `nativeStackStage`.

Its stdout and JSON artifact contain only fixed stage labels, route counts,
tree digests, and SHA-256 values. Browser console strings, invitation
fragments, mailbox addresses, OTPs, authorizations, and request bodies remain
in process memory and are never serialized.

## Real sender sign-in smoke

`sender-signin-smoke.mjs` is the release check that does not fake OpenKey
(TC-994). Each run makes a new throwaway OpenKey account with a random public
`@mailinator.com` inbox and email OTP, signs it in to Share, approves each
OpenKey review, creates a link-only share and opens it in a fresh browser
context. OpenKey, the owner Node and the registry are all production.

```bash
npm run test:e2e:sender-signin                                  # live share.tinycloud.xyz
npm run build && SHARE_SMOKE_CANDIDATE=dist npm run test:e2e:sender-signin  # this checkout
```

It prints one JSON line (also written to `SHARE_SMOKE_ARTIFACT`): approval
prompts for sign-in and for the share, timings, and on failure the stage, the
copy Share showed, and each failed or pending request with its status or
network error and timing. The inbox, code, address and link stay in memory.
`SHARE_SMOKE_MAX_SIGNIN_PROMPTS` (default 2) and
`SHARE_SMOKE_MAX_SHARE_PROMPTS` (default 1) fail a run that asks the sender
for more approvals. `.github/workflows/sender-signin-smoke.yml` runs it on
pull requests (candidate), after each production deploy, and daily. OpenKey's
release checks run the same script against production Share.
