# Share host deployment

The deploy build is environment-only. It emits
`/.well-known/tinycloud-share/config.json` from one validated
`SHARE_TRUST_BUNDLE`; no trust key or signer secret is committed to the
repository. A normal `npm run build` remains a source build and does not
require deployment secrets.

Required production variables:

- `SHARE_TRUST_BUNDLE` or `SHARE_TRUST_BUNDLE_FILE`: the strict
  `tinycloud.share-email-trust-bundle/v1` public document also mounted into
  tinycloud-node and OpenCredentials. It contains the Share, registry, node,
  witness, issuer, and enrollment bindings. Fixture, loopback, and
  placeholder identities are rejected.
- `SHARE_SENDER_PRIVATE_KEY`: a separately delivered server secret. It is
  checked against the sender identity and is never part of the trust bundle,
  capability response, or browser JavaScript.
- `SHARE_SENDER_CAPABILITY_JSON` or `SHARE_SENDER_CAPABILITIES_JSON`:
  authenticated-host capability provider output for the sender session. Each
  entry describes only an authorized exact KV or named-SQL read and bounded
  expiry; it does not pre-bind a recipient email and contains no signing
  secret.
- `SHARE_AUTH_USERS_JSON`: authenticated sender records with scrypt password
  hashes. The host issues a fresh opaque session after successful login; no
  environment secret is ever used as a cookie value.
- `SHARE_BINDING_STORE_PATH`: durable, private path or mounted durable store for
  public binding records. An in-memory store is permitted only for the explicit
  hermetic fixture composition.

The Node, OpenCredentials, and registry upstream destinations are not separate
deployment variables. They are derived directly from `nodeOrigin`,
`credentialsOrigin`, and `registryOrigin` in the validated trust bundle. Legacy
`*_TRANSPORT_ORIGIN` overrides are rejected. The only alternate routing shape
is the explicit hermetic test resolver described below; it must name the exact
bundle origin and may target loopback only.

Run the deploy checks and build with the secret manager injected:

```sh
npm run check:deploy-config
npm run build:deploy
HOST=0.0.0.0 PORT=8787 npm run start:deploy
```

The production host requires the exact Share origin on login/signing requests,
strict JSON/body and origin limits, an idempotency key, and a capability-bound
signing request. The sender explicitly selects one listed capability, enters
one canonical recipient, chooses a bounded expiry, reviews the exact
recipient/resource/action/expiry, and confirms before sending. The server
re-derives the selected capability from the authenticated session for every
sign, binding, and upload request. Missing trust, signer, authenticated user
records, durable binding storage, or registry configuration disables the
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
