# Share API operations

Pages must set `SHARE_API_ORIGIN` to the deployed API's origin-only HTTPS URL,
such as `https://api.share.tinycloud.xyz`. The root Pages Function rejects
HTTP, credentials, paths, queries, fragments, and missing values; it proxies
only readiness, well-known, registry, Share API, and email-share routes. All
other requests fall through to Pages assets/SPA. Browser origin and upstream
host are canonicalized and credential cookies are retained.

The `share-api` CVM persists `/var/lib/tinycloud/share` and uses auth-only
environment by default. `authReady` means nonce, OpenKey proof, replay,
origin, and session issuance work. `senderReady` additionally requires a
configured sender capability and binding store. Without that capability,
sender actions fail closed with JSON `503 sender_not_ready`; no authority is
invented during CVM creation.

Record the merged main commit and image provenance, create/update the CVM,
attach `api.share.tinycloud.xyz` through authenticated Cloudflare, set the
Pages variable, and deploy Functions. Verify public TLS, readiness, nonce,
well-known JSON, and the sender boundary. Roll back by restoring the prior
Pages deployment and CVM image/commit. Do not send email during smoke tests.
