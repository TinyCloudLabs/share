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
it uses the shipped HTTP transport and production verifier. The test may use
a capture delivery port, but it does not replace verifier logic or simulate a
successful claim.

The native matrix is deliberately explicit: Share vectors/tests/typecheck/build;
Node format, focused clippy/tests, mounted/config-readiness, and the feasible
full workspace tests/clippy; OpenCredentials normal, PostgreSQL, dstack,
dstack/PostgreSQL, SD-JWT, format/clippy, provider-boundary, and
config-readiness checks. The joined command is run twice from clean state. Only
fixtures started by that command may be stopped between runs.

The capture adapter is a hermetic implementation of the production delivery
port. It is compiled only with `email-claim-fixture`; production composition
constructs `ResendDeliveryPort` and rejects capture/provider mixing. The real
Resend smoke command is separately committed and refuses to run unless an
operator supplies an explicit controlled recipient and complete signed request.

Release stamping uses runtime-provided exact expected heads. Do not put a
release commit hash inside the commit that creates it. The evidence descriptor
records the immutable contract commit and final owning heads; its parent and a
separately recorded evidence commit identify the evidence snapshot without a
self-referential hash.

Generate a redacted, reproducible evidence record after a successful run:

```sh
npm run release:evidence -- --output .release-evidence/email-claim.json
```

The record includes UTC timestamp, exact heads, manifest/digest, commands,
tool versions, artifact hashes, and owned-process cleanup. It never records
claim material, private keys, provider payloads, or authorization values.
The real Resend smoke lane is intentionally separate and must receive an
explicit controlled recipient before it can run.
