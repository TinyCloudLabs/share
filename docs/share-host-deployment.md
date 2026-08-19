# Share host deployment

Exact-email sharing is the production default: the reviewed Compose file sets
both `SHARE_SENDER_ENABLED` and `SHARE_ACCOUNTLESS_RECEIVER_ENABLED` to `true`
when no explicit value is supplied. This keeps the durable sender-binding path
and the first-class accountless receiver coupled: a normal image rollout cannot
publish a receiver that cannot be sent an exact-email share. Compose defaults
`SHARE_BINDING_STORE_PATH` to the persistent
`/var/lib/tinycloud/share/bindings.ndjson` volume path. In that mode
both flags may be explicitly set to `false` together for an auth-only rollback;
binding-store settings are then ignored even if stale values remain in the
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
non-browser caller may provide the bounded `x-tinycloud-upload-attestation`
header plus canonical JSON `x-tinycloud-retention`; the Node-signed attestation
is checked against the body before it is consumed and stripped at the registry
boundary.
dedicated upload key is created once in the persistent CVM volume and signs a
one-minute authorization bound to the session, body digest, body size, and
retention; this key is not sender/email authority. The registry independently
checks those bounds with `REGISTRY_LINK_UPLOAD_PUBLIC_KEY`.
The upload budget and upload-attestation JTI are reserved through the registry
Worker's `/internal/upload-authorizations` endpoint, backed by its
`UploadAuthorization` Durable Object. The Share host signs each exact store
operation with the dedicated registry-upload key; it never treats the local
NDJSON binding journal as replay or quota authority. The production host fails
closed when the Worker, binding, signature configuration, or Durable Object is
unavailable. The Worker binding and Durable Object provide atomic uniqueness
across restarts and independent Share replicas.
Unauthenticated writes and direct `POST /registry/blobs` requests fail closed;
public CID reads remain available to recipients.

Static sender-authority variables (a server-held sender private key or a
pre-issued capability descriptor) are not a supported deployment shape; the
production entrypoint and `npm run check:deploy-config` both refuse to start
if any are set. Sender identity is established exclusively through an
authenticated OpenKey/SDK wallet session (`POST /api/share/auth/openkey`),
which the Share host verifies against the same manifest-bearing SIWE message
the TinyCloud SDK signs. The browser asks for one user approval, reuses that
proof for Share authentication, and sends subsequent bootstrap signatures to
OpenKey's bounded delegated signer. Share data uses the enshrined
`applications` space under `xyz.tinycloud.share/`; custom space hosting is
outside OpenKey's zero-gesture bootstrap allowlist. The host accepts the SDK's
delegated `did:key` SIWE URI, but still requires its own single-use nonce, exact
Share domain, a ReCap resource, a one-hour session expiry, and the controlling
wallet signature before issuing a session. `SHARE_SENDER_ENABLED=true` also requires a usable durable
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

The deploy build emits `/.well-known/tinycloud-share/config.json` from exactly
one validated trust bundle: `SHARE_TRUST_BUNDLE`, `SHARE_TRUST_BUNDLE_FILE`, or
the reviewed `config/trust-bundle.production.json` selected by
`SHARE_TRUST_BUNDLE_SOURCE=committed`. No signer secret is committed to the
repository under any of them — the trust bundle carries public keys only, and
the sender signing key is not expressible in deployment configuration at all. A
normal `npm run build` remains a source build and does not require deployment
secrets.

Required production variables:

- `SHARE_RELEASE_PROVENANCE`: a strict manifest binding the release identifier,
  protected-merge commits for Share/Node/OpenCredentials/SDK, the exact Share
  image digest, configuration digest, migration version, and an immutable
  rollback image/release target. The deploy validator rejects a composition
  without this manifest or with a mismatched Share image.
- `SHARE_SENDER_ENABLED`: optional strict boolean string. Omitted or `false`
  selects auth-only mode; `true` enables the sender and requires a healthy
  wallet-rooted authentication path and a usable durable binding store.
- `SHARE_TRUST_BUNDLE_SOURCE`: `committed` in production. See
  "Where the trust bundle comes from" below.
- `SHARE_TRUST_BUNDLE` or `SHARE_TRUST_BUNDLE_FILE`: the strict
  `tinycloud.share-email-trust-bundle/v1` public document also mounted into
  tinycloud-node and OpenCredentials. It contains the Share, registry, node,
  witness, issuer, and enrollment bindings. Fixture, loopback, and
  placeholder identities are rejected. Required unless
  `SHARE_TRUST_BUNDLE_SOURCE=committed`; supplying either alongside `committed`
  is a startup error, so a stale value can never silently win.
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
- `SHARE_SENDER_ROOT_KEY_PATH` (sender-enabled only) is the persistent sender
  root seed. It defaults to `/var/lib/tinycloud/share/sender-root.key` and must
  be a normalized strict descendant of the persistent Share volume. The host
  creates it once at 0600 and reuses it across restarts; each authenticated
  wallet's sender `did:key` is derived from that seed and its verified
  `did:pkh` principal, so a session for one wallet can never sign under
  another wallet's sender identity. There is deliberately no inline variant: a
  sender secret is never expressible in deployment configuration. `senderReady`
  means the sender path is configured and can serve an authenticated session,
  not that any particular capability exists; a session with no admitted
  capability gets `409 sender_capability_required` per request.
- `SHARE_BINDING_STORE_ROOT` is the verified persistent mount root and is fixed
  by the production Compose file at `/var/lib/tinycloud/share`. A separately
  mounted durable root may be supplied only when that mount is explicitly
  provisioned and verified before startup.
- `SHARE_BINDING_STORE_PATH` (sender-enabled only, optional in the Compose
  deployment) must be a normalized strict descendant of that root; traversal,
  `/tmp`, sibling-prefix paths, and unmounted absolute paths are rejected. It
  defaults to `/var/lib/tinycloud/share/bindings.ndjson`. An in-memory store is
  permitted only for the explicit hermetic fixture composition.

## Where the trust bundle comes from

The trust bundle holds no secret. All seventeen fields are public: five HTTPS
origins, two `did:web` identifiers, two key ids, two **public** Ed25519 keys,
two key versions and two enablement booleans. Fifteen of them are already
republished verbatim to anyone who asks at
`/.well-known/tinycloud-share/config.json`. The two that are not are
`returnOrigin`, which tinycloud-node requires to equal `shareOrigin`, and
`issuerKid`, a fragment of the published `issuerDid`. The one real secret in the
sender path is deliberately not in this document and not expressible in
deployment configuration at all; it is derived per request from an authenticated
OpenKey session. tinycloud-node and OpenCredentials already mount this same
document as a plain, unsealed, read-only JSON file.

Two sources are supported, selected by `SHARE_TRUST_BUNDLE_SOURCE`:

- `environment` (available for non-production compositions): the host reads
  `SHARE_TRUST_BUNDLE` or `SHARE_TRUST_BUNDLE_FILE`. In the CVM,
  `compose.share-api.yml` base64-decodes `SHARE_TRUST_BUNDLE_BASE64` out of
  Phala sealed environment storage into `/tmp`.
- `committed` (the production setting): the host reads `config/trust-bundle.production.json`, the
  reviewed document baked into the image. No trust material is in the
  environment at all.

`committed` exists because sealing bought nothing and cost a great deal. A Phala
sealed environment can only be replaced wholesale, so rewriting the bundle also
rewrites the co-sealed `CLOUDFLARE_TUNNEL_TOKEN` — which cannot be regenerated
from here, because `CLOUDFLARE_API_TOKEN` lacks tunnel scope and the CVM has no
SSH keys. A document of public keys was therefore effectively immutable in
production.

A reviewed file is also the stronger integrity control. It is covered by branch
protection and pull-request review and pinned into the immutable image digest
that `SHARE_RELEASE_PROVENANCE` already binds, unlike a fetched URL or an
unsealed variable that anyone able to influence a request or a deploy could
change. Independent validation still applies on both sides: this host rejects
placeholder, loopback and fixture identities, and tinycloud-node's
`share_v2::compose` fails closed and loudly when the configured
`nodeInvitationPublicKey` is not the key it derives and signs with, naming both
keys (TC-359, node commit `8c9ae2d`). A wrong bundle is a boot error, not silent
non-delivery.

### Correcting `nodeInvitationPublicKey`, or any other trust value

`config/trust-bundle.production.json` pins
`nodeInvitationPublicKey: 5gcZDCwHRoW6iEzPPGUdtiGMzWBj6aGtTlRBVERr1GI`. That is
the real key, read on 2026-07-29 from the production CVM's own
`GET https://tee.node.tinycloud.xyz/.well-known/tinycloud/node-keys` once
tinycloud-node `1.13.0` was deployed (TC-369). It replaced the known-wrong
OpenCredentials development fallback the bundle was first committed with, which
production had been publishing since TC-359.

The procedure below is what that correction followed, and is what any future
key change — a node redeploy that rotates the derived key, a second node —
should follow too:

1. Read the real key. `curl -fsS
https://tee.node.tinycloud.xyz/.well-known/tinycloud/node-keys` and take
   `shareInvitationPublicKey`.
2. Edit the one `"nodeInvitationPublicKey"` line in
   `config/trust-bundle.production.json`. Change nothing else.
3. Open a pull request. The merge gate runs `npm test`, which asserts the
   document is a strict production bundle and that the host republishes it
   unchanged, and `node --test scripts/validate-deploy-config.test.mjs`.
4. Merge, let `share-api-image.yml` publish, and record the new GHCR digest.
5. Update the CVM's **compose** with that `SHARE_API_IMAGE` digest and
   `SHARE_TRUST_BUNDLE_SOURCE: committed`. Do not submit an environment file:
   the sealed `CLOUDFLARE_TUNNEL_TOKEN` must not be rewritten.
6. Verify. `curl -fsS
https://share.tinycloud.xyz/.well-known/tinycloud-share/config.json` reports
   the new key, and `/health/readiness` still reports `authReady: true`.

Two other holders of the same value must move in the same change, or delivery
still fails at the verifier:

- **OpenCredentials witness.** `SHARE_EMAIL_TRUSTED_NODE_PUBLIC_KEY` defaults to
  the same fixture literal in
  `rust/opencredentials_witness/src/share_email/runtime.rs`. Set it explicitly.
- **tinycloud-node.** Its own mounted `share-email-trust-bundle.json`
  (`TINYCLOUD_SHARE_EMAIL__TRUST_BUNDLE_PATH`) carries
  `nodeInvitationPublicKey` too. That file is already plain and read-only, so
  this is a mount change, not a re-seal.

Rolling back is the same move reversed: set `SHARE_TRUST_BUNDLE_SOURCE` back to
`environment` in the compose and redeploy the previous image digest. The sealed
`SHARE_TRUST_BUNDLE_BASE64` is never deleted, so the old path stays available.

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
   the persistent sender root seed path writable. No deployment variable
   carries sender authority: a wallet's sender identity is derived at request
   time from an authenticated OpenKey session, and its capability is admitted
   per session. The composition boots and reports `senderReady: true`. A
   wallet's sends are only authorized once its derived `senderDid` appears in
   the node's operator-supplied authority material, so read that DID from
   `GET /api/share/sender-identity` and provision it on the node before
   enabling delivery for that wallet.
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
