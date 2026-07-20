# Share host deployment

The deploy build is environment-only. It emits
`/.well-known/tinycloud-share/config.json` from one validated
`SHARE_TRUST_BUNDLE`; no trust key or signer secret is committed to the
repository. A normal `npm run build` remains a source build and does not
require deployment secrets.

Required production variables:

- `SHARE_TRUST_BUNDLE` or `SHARE_TRUST_BUNDLE_FILE`: JSON v1 bundle containing
  the Share, registry, node, witness, issuer, enrollment, and sender key
  bindings. It must use `environment: "production"`; fixture, loopback, and
  placeholder identities are rejected.
- `SHARE_SENDER_CAPABILITY_JSON`: authenticated-host capability provider output
  for the sender session. Its private key is consumed only by the host adapter
  and is never serialized to browser JavaScript.
- `SHARE_SESSION_SECRET`: session binding secret delivered by the deployment
  secret manager.
- `SHARE_BINDING_STORE_PATH`: durable, private path or mounted durable store for
  public binding records. An in-memory store is permitted only for the explicit
  hermetic fixture composition.
- `SHARE_REGISTRY_ORIGIN`: canonical HTTPS registry origin, normally
  `https://registry.tinycloud.xyz`.

Run the deploy checks and build with the secret manager injected:

```sh
npm run check:deploy-config
npm run build:deploy
SHARE_DEPLOY_STARTUP=true npm run preview -- --host 0.0.0.0 --port 8787
```

The host adapter requires the exact Share origin on authenticated requests,
strict JSON/body and origin limits, an idempotency key, and a capability-bound
signing request. It exposes only a public capability descriptor and signatures
for the exact envelope/invitation binding. Missing trust, signer, session,
durable binding storage, or registry configuration disables the capability.

For local tests, use only the composition owned by `test/e2e-email`: set
`SHARE_TRUST_BUNDLE_ALLOW_TEST=true`, use a generated `environment: "test"`
bundle, point `SHARE_REGISTRY_ORIGIN` at the ephemeral registry listener, and
use the loopback Resend provider. Do not put those values in `public/`, a
production bundle, or a committed fixture.
