# Share host deployment

The auth-only composition is intentional and is the default:
`SHARE_SENDER_ENABLED` is `false` when omitted. Compose defaults
`SHARE_BINDING_STORE_PATH` to the persistent
`/var/lib/tinycloud/share/bindings.ndjson` volume path. In that mode
binding-store settings are ignored even if stale values remain in the
environment. `/health/readiness` reports
`{ "authReady": true, "senderReady": false }`, and signing and binding remain
fail-closed with JSON `503 sender_not_ready`. The trust bundle may truthfully
set `nodeEnabled=false` while retaining the validated public node identity;
OpenKey authentication remains ready, the public configuration preserves the
disabled status, and no email-share authority is asserted.

An authenticated OpenKey session can still create a possession-based encrypted
share. Its only write path is `POST /api/share/link-only/registry/blobs`: raw,
create-only blobs up to 64 KiB, retention bounded to eight days, with a
per-session upload budget. The Share host validates the session before
forwarding only the protocol headers and encrypted body to the registry. A
dedicated upload key is created once in the persistent CVM volume and signs a
one-minute authorization bound to the session, body digest, body size, and
retention; this key is not sender/email authority. The registry independently
checks those bounds with `REGISTRY_LINK_UPLOAD_PUBLIC_KEY`.
Unauthenticated writes and direct `POST /registry/blobs` requests fail closed;
public CID reads remain available to recipients.

Static sender-authority variables (a server-held sender private key or a
pre-issued capability descriptor) are not a supported deployment shape; the
production entrypoint and `npm run check:deploy-config` both refuse to start
if any are set. Sender identity is established exclusively through an
authenticated OpenKey/SDK wallet session (`POST /api/share/auth/openkey`),
which the Share host verifies against the signed SIWE-style message before
issuing a session. `SHARE_SENDER_ENABLED=true` also requires a usable durable
binding-store path, and sender enablement requires `nodeEnabled=true`. The
Phala CVM deployment uses `Dockerfile.share-api` and
`compose.share-api.yml`; mount secrets through the CVM secret manager and keep
the persistent volume at `/var/lib/tinycloud/share`.

Cloudflare Pages functions proxy only the exact auth/session, readiness, and
well-known paths to `https://api.share.tinycloud.xyz`; SPA routes remain static.

Webhook egress is a separate release boundary. The Node registration and
dispatcher require canonical HTTPS callbacks on port 443, reject userinfo,
fragments, and reserved/private address ranges, disable redirects, and pin a
fresh public DNS result for each delivery. The production network policy must
also deny loopback, link-local, private, carrier-grade NAT, multicast,
unspecified, documentation, and other reserved IPv4/IPv6 destinations, and
must deny all non-443 egress from the webhook process. The deployment evidence
must retain the policy revision and its adversarial SSRF/redirect test result.

The deploy build is environment-only. It emits
`/.well-known/tinycloud-share/config.json` from one validated
`SHARE_TRUST_BUNDLE`; no trust key or signer secret is committed to the
repository. A normal `npm run build` remains a source build and does not
require deployment secrets.

Required production variables:

- `SHARE_RELEASE_PROVENANCE`: a strict manifest binding the release identifier,
  protected-merge commits for Share/Node/OpenCredentials/SDK, the exact Share
  image digest, configuration digest, migration version, and an immutable
  rollback image/release target. The deploy validator rejects a composition
  without this manifest or with a mismatched Share image.
- `SHARE_SENDER_ENABLED`: optional strict boolean string. Omitted or `false`
  selects auth-only mode; `true` enables the sender and requires a healthy
  wallet-rooted authentication path and a usable durable binding store.
- `SHARE_TRUST_BUNDLE` or `SHARE_TRUST_BUNDLE_FILE`: the strict
  `tinycloud.share-email-trust-bundle/v1` public document also mounted into
  tinycloud-node and OpenCredentials. It contains the Share, registry, node,
  witness, issuer, and enrollment bindings. Fixture, loopback, and
  placeholder identities are rejected.
- `SHARE_SENDER_PRIVATE_KEY`, `SHARE_SENDER_CAPABILITY_JSON`, and
  `SHARE_SENDER_CAPABILITIES_JSON` are legacy static sender-authority
  variables and are forbidden. `npm run check:deploy-config` and the
  production entrypoint both reject a composition that sets any of them.
  Sender authority comes exclusively from an authenticated OpenKey/SDK
  wallet session: the Share host verifies a single-use OpenKey signature,
  resolves the signing address to a `did:pkh:eip155:<chain>:<address>`, and
  only then issues an opaque sender session bound to that wallet.
  `SHARE_AUTH_USERS_JSON` is an optional legacy fallback containing
  scrypt-password records; the product UI does not request those passwords.
- `SHARE_BINDING_STORE_ROOT` is the verified persistent mount root and is fixed
  by the production Compose file at `/var/lib/tinycloud/share`. A separately
  mounted durable root may be supplied only when that mount is explicitly
  provisioned and verified before startup.
- `SHARE_BINDING_STORE_PATH` (sender-enabled only, optional in the Compose
  deployment) must be a normalized strict descendant of that root; traversal,
  `/tmp`, sibling-prefix paths, and unmounted absolute paths are rejected. It
  defaults to `/var/lib/tinycloud/share/bindings.ndjson`. An in-memory store is
  permitted only for the explicit hermetic fixture composition.

The Node, OpenCredentials, and registry upstream destinations are not separate
deployment variables. They are derived directly from `nodeOrigin`,
`credentialsOrigin`, and `registryOrigin` in the validated trust bundle. Legacy
`*_TRANSPORT_ORIGIN` overrides are rejected. The only alternate routing shape
is the explicit hermetic test resolver described below; it must name the exact
bundle origin and may target loopback only.

Atomic enablement sequence:

1. Run `npm run check:deploy-config` against the canonical public bundle and
   provenance manifest; the check rejects any legacy static sender-authority
   variable.
2. Start OpenCredentials with migrations and durable-storage readiness healthy,
   but keep `SHARE_EMAIL_CAPABILITY=false` until provider, database, CA, and
   trust-bundle inputs are complete.
3. `SHARE_SENDER_ENABLED=true` requires the durable binding store mounted and
   a wallet-rooted capability-issuance path for the sender session; no
   deployment variable substitutes for that path, so this composition is not
   yet a supported production shape.
4. Enable OpenCredentials through its production renderer, confirm healthy
   storage and capability advertisement, then run the controlled E2E.
5. If either readiness gate degrades, disable both flags and restore the last
   known-good image/configuration before retrying.

Run the deploy checks and build with the secret manager injected:

```sh
npm run check:deploy-config
npm run build:deploy
HOST=0.0.0.0 PORT=8787 npm run start:deploy
```

The production host requires the exact Share origin on OpenKey and signing requests,
strict JSON/body and origin limits, an idempotency key, and a capability-bound
signing request. The sender explicitly selects one listed capability, enters
one canonical recipient, chooses a bounded expiry, reviews the exact
recipient/resource/action/expiry, and confirms before sending. The server
re-derives the selected capability from the authenticated session for every
sign, binding, and upload request. Missing trust, signer, authenticated user
binding, durable binding storage, or registry configuration disables the
capability. Sessions are opaque, per-user, Secure, HttpOnly, SameSite,
path-scoped, and expiring.

The production reverse proxy has route-specific method and media-type rules,
bounded request bodies, and explicit request/response header allowlists. Cookie,
Authorization, Host, forwarding, hop-by-hop, content-length, transfer-encoding,
Set-Cookie, redirect, CSP, cache, and other Share security-header mutation are
never forwarded across the service boundary.

For local tests, use only the composition owned by `test/e2e-email`. It may set
`SHARE_HERMETIC_COMPOSITION=true` and provide
`SHARE_HERMETIC_UPSTREAMS_JSON` with `{origin, transportOrigin}` entries bound
to the validated Node, OpenCredentials, and registry origins. This is the
canonical-DNS-to-loopback resolver boundary; it is rejected by deploy
validation and cannot be supplied by a production process. Do not put those
values in `public/`, a production bundle, or a committed fixture.
