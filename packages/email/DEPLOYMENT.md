# Deploying the share email Worker

**Nothing in this package deploys on merge.** No workflow in the repository
runs `wrangler deploy` at all. The merge gate
(`.github/workflows/share-sdk.yml`) type-checks and runs this package's tests
— since TC-371 the root `tsconfig.json` includes `packages` and `npm test`
runs `vitest run packages` — but it publishes nothing. The other two
workflows build and smoke the `share-api` container image, which is unrelated
to this Worker. Deployment is a deliberate manual step, exactly as it is for
`packages/registry`.

## 1. Cloudflare resources

Account `9959301f03d2db1a5fcf5e004278d467`, zone
`29b3a489c28c19707f8a9dd91da9dc42` — the same pair `packages/registry`
already uses.

```sh
# D1 database for the idempotency ledger
npx wrangler d1 create tinycloud-share-email
# paste the returned id into wrangler.jsonc -> d1_databases[0].database_id
npx wrangler d1 execute tinycloud-share-email --remote --file migrations/0001_deliveries.sql
```

`wrangler.jsonc` ships with `database_id: ""` on purpose: the database does
not exist yet and this file must not claim an id that does not.

## 2. DNS and route

Add an orange-clouded `AAAA email.tinycloud.xyz -> 100::` (or a CNAME to the
zone apex) so the zone can route to a Worker, then the configured route
`email.tinycloud.xyz/*` takes effect on deploy. No Pages project is involved.

## 3. Secrets

```sh
npx wrangler secret put RESEND_API_KEY            # the value already used by the OpenCredentials witness
npx wrangler secret put NODE_INVITATION_KID       # e.g. did:web:node.tinycloud.xyz#invitation-key-1
npx wrangler secret put NODE_INVITATION_PUBLIC_KEY # base64url, 43 chars, 32 raw bytes
npx wrangler secret put DELIVERY_AUDIENCE         # the origin the Node stamps into openCredentialsAudience
```

`RESEND_API_KEY` exists today as a repository secret on OpenCredentials; it has
to be created as a Worker secret here. Do not copy its value into any file.

`NODE_INVITATION_KID` / `NODE_INVITATION_PUBLIC_KEY` are the Node's **enrolled**
invitation key. Production's published `nodeInvitationPublicKey` is still a
development fixture and the route that would publish the real one
(`GET /.well-known/tinycloud/node-keys`, TC-359 / TC-369) is merged but not
deployed. Until it is, take the real key from the Node operator out of band.
Setting the fixture here means every send is refused with `untrusted` — which
is the intended failure.

`DELIVERY_AUDIENCE` must be whatever the Node has configured as its
`credentials_origin`, because that is the value it signs into
`openCredentialsAudience` (`tinycloud-node-server/src/share_v2.rs`). Today that
is the OpenCredentials witness origin, e.g. `https://witness.credentials.org`.
When the Node is reconfigured to point at this service, change it here in the
same window as the Node change — a mismatch refuses, it never degrades.

## 4. Vars

Already in `wrangler.jsonc`, override only if an environment differs:

- `SHARE_ORIGIN` — `https://share.tinycloud.xyz`
- `NODE_ORIGIN` — `https://node.tinycloud.xyz`
- `EMAIL_FROM` — `TinyCloud Share <invite@share.tinycloud.xyz>`

The `invite@share.tinycloud.xyz` sender must be a verified Resend domain
identity, as it already is for the witness.

## 5. Deploy and verify

```sh
npx wrangler deploy --config wrangler.jsonc
curl -s https://email.tinycloud.xyz/health/readiness   # {"ready":true} once everything above is set
```

`/health/readiness` reports presence only, never a value. Then confirm the
fail-closed edges against the live Worker before wiring any sender to it:

```sh
# unsigned body -> 400 malformed
curl -s -o /dev/null -w '%{http_code}\n' -XPOST https://email.tinycloud.xyz/share/v2 \
  -H 'content-type: application/json' --data '{}'
# unknown route -> 404
curl -s -o /dev/null -w '%{http_code}\n' https://email.tinycloud.xyz/
```

## 6. Portability

There is nothing Cloudflare-specific beyond two bindings. The handler is a
plain `fetch(Request, env)`; storage is behind `D1DatabaseLike`, which is four
lines of SQLite; crypto is WebCrypto Ed25519. Moving this into a CVM means
supplying an HTTP server and a SQLite-backed `D1DatabaseLike`, nothing else.

## Rollback

`npx wrangler rollback` restores the previous deployment. The ledger is
append-only and forward-compatible: a rollback cannot cause a duplicate send,
because the primary key that prevents one is in D1, not in the Worker.
