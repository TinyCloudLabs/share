# Share CLI integration

The Share browser viewer and sender are the web adapter for the canonical
`@tinycloud/share-envelope` and `@tinycloud/share-sdk` packages produced by
`TinyCloudLabs/js-sdk`. The Node CLI is the other adapter. Both surfaces use
the same compact-v1 and inline-v2 link grammar, origin binding, CID checks,
AEAD verification, and redacted metadata contract.

## Agent contract

Keep a complete link, including its fragment, in one local process. The
fragment is bearer authority and must not be written to logs, shell history,
analytics, referrers, or cross-origin messages.

```sh
printf '%s' "$SHARE_URL" | npx -y @tinycloud/cli@latest share inspect - --json
printf '%s' "$SHARE_URL" | npx -y @tinycloud/cli@latest share receive - --output .
```

`share inspect` returns versioned redacted metadata. `share receive` verifies
before writing, creates the output exclusively, refuses symlink targets, and
prints only the output path unless `--stdout` is explicitly requested.

## Release sequencing

The js-sdk packages must be built and published before this consumer can pin
the eventual release in `package.json`. During cross-repository development,
use packed artifacts in a temporary directory only; do not commit `file:`,
branch, tarball, or floating `latest` dependencies. The post-merge release
gate is:

1. merge and publish `@tinycloud/share-envelope` and `@tinycloud/share-sdk`
   from js-sdk;
2. replace the temporary consumer pin with the exact released versions and
   regenerate `package-lock.json`;
3. run `npm ci`, the Share typecheck/build suites, and the CLI/web parity
   vectors from a clean checkout.

Production upload authority remains authenticated and session-bound. No
anonymous or plaintext registry upload is a valid release path.
