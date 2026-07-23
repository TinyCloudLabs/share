# Share API operations

Pages must set `SHARE_API_ORIGIN` to the exact literal
`https://api.share.tinycloud.xyz`. The root Pages Function rejects whitespace,
alternate ports or hosts, HTTP, credentials, paths, queries, fragments, and
missing values; it proxies
only readiness, well-known, registry, Share API, and email-share routes. All
other requests fall through to Pages assets/SPA. Browser origin and upstream
host are canonicalized and credential cookies are retained.

The `share-api` CVM persists `/var/lib/tinycloud/share` and defaults
`SHARE_SENDER_ENABLED` to `false` (auth-only), ignoring stale sender settings in
that mode. `authReady` means nonce, OpenKey proof, replay, origin, and session
issuance work. `SHARE_SENDER_ENABLED=true` requires complete valid sender key,
capability, and writable durable binding-store material or startup fails.
Without an enabled sender, sender actions fail closed with JSON
`503 sender_not_ready`; no authority is invented during CVM creation.

Record the merged main commit and image provenance, create/update the CVM,
attach `api.share.tinycloud.xyz` through authenticated Cloudflare, set the
Pages variable, and deploy Functions. Verify public TLS, readiness, nonce,
well-known JSON, and the sender boundary. Roll back by restoring the prior
Pages deployment and CVM image/commit. Do not send email during smoke tests.
