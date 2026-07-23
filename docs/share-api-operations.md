# Share API operations

Pages must set `SHARE_API_ORIGIN` to the exact literal
`https://api.share.tinycloud.xyz`. The root Pages Function rejects whitespace,
alternate ports or hosts, HTTP, credentials, paths, queries, fragments, and
missing values; it proxies
only readiness, well-known, registry, Share API, and email-share routes. All
other requests fall through to Pages assets/SPA. Browser origin and upstream
host are canonicalized and credential cookies are retained.

The `share-api` CVM persists `/var/lib/tinycloud/share` and pins
`SHARE_SENDER_ENABLED=false` (auth-only), ignoring stale sender settings in
that mode. Deploy `compose.share-api.yml` with `SHARE_API_IMAGE` set to the
exact merged-main GHCR digest, `SHARE_TRUST_BUNDLE_BASE64` set to the
base64-encoded validated public bundle through Phala sealed environment
storage, and `CLOUDFLARE_TUNNEL_TOKEN` injected through the same storage. The
pinned Cloudflare Tunnel sidecar exposes only the internal
Share API service at `api.share.tinycloud.xyz`; the API container publishes no
host port. `authReady` means nonce, OpenKey proof, replay, origin, and session
issuance work. `SHARE_SENDER_ENABLED=true` requires complete valid sender key,
capability, and writable durable binding-store material or startup fails.
Without an enabled sender, sender actions fail closed with JSON
`503 sender_not_ready`; no authority is invented during CVM creation.

Record the merged main commit and image provenance, create/update the CVM,
attach `api.share.tinycloud.xyz` through authenticated Cloudflare, set the
Pages variable, and deploy Functions. Verify public TLS, readiness, nonce,
well-known JSON, and the sender boundary. Roll back by restoring the prior
Pages deployment and CVM image/commit. Do not send email during smoke tests.
