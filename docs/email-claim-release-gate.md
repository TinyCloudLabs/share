# Exact-email release gate

The convergence owner stamps the three immutable release heads and runs the
joined gate from this worktree. The gate refuses ancestor pins, dirty sibling
worktrees, stale contract manifests, missing local PostgreSQL, and missing
browser fixtures.

```sh
SHARE_RELEASE_HEAD=<exact-share-head> \
TINYCLOUD_NODE_RELEASE_HEAD=<exact-node-head> \
OPEN_CREDENTIALS_RELEASE_HEAD=<exact-opencredentials-head> \
npm run test:e2e:email
```

`npm run test:e2e:email` runs the frozen vector validator, Share test suite,
Share typecheck, production build, applicable Node/OpenCredentials gates, and
the joined KV + constrained named-SQL browser matrix. The browser loads the
same-origin public config artifact and authenticated sender capability route;
it uses the shipped HTTP transport and production verifier. The joined fixture
composes the production Resend adapter against a loopback HTTP provider that
accepts the real request and records only the provider response artifact.
Capture delivery remains available only to lower-level fixture tests and cannot
be selected by the mounted composition.

The browser matrix also asserts that the sender reports an accepted request
without claiming arrival, the recipient link is scrubbed before application
network work, scanner GET is inert, **Open document** is the only magic-link
activation, holder material is not persisted or placed in request URLs, and
recipient failures never expose document content. It runs the sender and
recipient at 390px and desktop widths with reduced motion, checks live-region
and focus semantics, and verifies the hardened Markdown content boundary.
Deterministic DOM-state coverage for OTP, resend cooldown, retry, forget, and
terminal error states lives in `test/e2e-email/ui-contract.test.ts` and is
included by the root Vitest configuration.

The native matrix is deliberately explicit: Share vectors/tests/typecheck/build;
Node format, focused clippy/tests, mounted/config-readiness, and the feasible
full workspace tests/clippy; OpenCredentials normal, PostgreSQL, dstack,
dstack/PostgreSQL, SD-JWT, format/clippy, provider-boundary, and
config-readiness checks. The joined command is run twice from clean state. Only
fixtures started by that command may be stopped between runs.

The loopback provider is hermetic and accepts the unchanged production Resend
wire request, including the provider idempotency key. The real Resend smoke
command is separately committed and refuses to run unless an operator supplies
an explicit controlled recipient and complete signed request.

Release stamping uses runtime-provided exact expected heads. Do not put a
release commit hash inside the commit that creates it. The evidence descriptor
records the immutable contract commit and final owning heads; its parent and a
separately recorded evidence commit identify the evidence snapshot without a
self-referential hash.

Each joined gate execution writes an immutable run record and a hashed execution
log under `.release-evidence/runs/`. The record is written even on failure and
contains the exact heads, start/end/duration, exit status, command, toolchain,
coverage, artifact hashes, and owned-process cleanup result. Generate the final
redacted snapshot only after two distinct clean records pass verification:

```sh
npm run release:evidence -- --output .release-evidence/email-claim.json
```

The generator refuses missing, failed, duplicate, tampered, stale, dirty, or
toolchain-mismatched run records. It never records claim material, private
keys, provider payloads, or authorization values. SIWE origin/main versus
feature-head provenance is marked `not-run` unless the integration lane supplies
both exact heads and the same-toolchain comparison metadata.
The real Resend smoke lane is intentionally separate and must receive an
explicit controlled recipient before it can run.
