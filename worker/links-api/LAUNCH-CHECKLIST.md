# links-api launch checklist (operator)

State at launch: the Worker `links-api` is live at `https://api.tinycloud.xyz` (version `bba05bcd`); the D1 database `links-api` has id `c26a26cc-7595-42a4-95ae-0f9aec08a228` and `migrations/0001_init.sql` is applied; the smoke of step 7 passed against the live API. With `LINKS_READ_SIGNERS` unset, the Worker accepts no signer on the authenticated read path, so every read counts against the per-address read limit. The allow-list is set when a node signer is registered (contract §11.7). Order follows contract 7.9: the API goes first.

## Before create

- [ ] The vector copy and its pin match the final contract (`test/vectors/short-links-api-vectors.json`, `VECTORS_SHA256` in `test/support/vectors.ts`); `npm run vectors` passes.
- [ ] `npm ci`, `npm run typecheck` and `npm test` pass at the commit to deploy.
- [ ] Approval for the custom domain and the Cloudflare plan is recorded.

## Create and deploy

1. **D1 database.** Created as `links-api`; its id is in `wrangler.toml` (`database_id`).
2. **Migration.** `npx wrangler d1 migrations apply links-api --remote` (applies `migrations/0001_init.sql`).
3. **Secret and variables.** `npx wrangler secret put ADDRESS_SALT` (16 or more random characters). Check `LINKS_AUDIENCE` (`https://api.tinycloud.xyz`) and `LINKS_CORS_ORIGINS` (`https://share.tinycloud.xyz`) in `wrangler.toml`.
   **Node read allow-list.** Set `LINKS_READ_SIGNERS` as a Worker secret or dashboard variable (not in `wrangler.toml`, not in the repository): `[{"label":"service:node","did":"<the nodeId field of https://node.tinycloud.xyz/info>"}]`. Never list a test seed. `LINKS_READ_AUTH_LIMIT` is optional (default 6,000 a minute). A list that does not validate stops the Worker from serving (every request answers 500). Set `LINKS_READ_SIGNERS` only with an immediate smoke (one read of any 26-character id: 404 is healthy): a 500 on every request means the variable is malformed, and the first action is to unset it.
   **Rotation.** Set the list to the old and the new key (two at once), deploy the node with the new key, confirm `reads.authenticated` still counts, then set the list to the new key only.
4. **OpenKey API key.** Generate 32 random bytes, base64url, as the secret; store only `base64url(SHA-256(secret))`. Insert the row (`key_id` is 8 alphanumeric characters):
   `INSERT INTO api_keys (key_id, service, allowed_types, secret_sha256, created_at) VALUES ('<keyId>', 'openkey', '["openkey-login"]', '<hash>', <epoch seconds>);`
   Give OpenKey `tlk_<keyId>_<secret>` out of band. Rotation: add the second key, deploy it to OpenKey, then `UPDATE api_keys SET revoked_at = <epoch seconds> WHERE key_id = '<old>';`.
5. **Worker.** `npx wrangler deploy` (the cron trigger `* * * * *` runs the sweep and the health line every minute).
6. **Custom domain and DNS.** Attach `api.tinycloud.xyz` to the Worker as a custom domain (this creates the DNS record). No other route is declared.
7. **Smoke.** `node scripts/local-smoke.ts https://api.tinycloud.xyz` (creates, reads, takes and deletes test records that expire on their own).
8. **Post-deploy smokes for the node read.** (a) After the node has made a signed read, the next `links.health` line shows `reads.authenticated` above 0 (no response field says whether the header was recognised). A node that sends a header that is not the canonical JSON of the contract is served as an ordinary read under the per-address limit, so after the node ships its signing commit this smoke must show `reads.authenticated` increasing; if it stays at 0, the node's header is not being recognised. (b) A response from the API carries a `Date` header (for example `curl -sI https://api.tinycloud.xyz/v1/links/<any 26-character id>`).

## Alerts

Log sink: Workers Logs, enabled in `wrangler.toml` with invocation logs off (README, "Where the lines go"). Do not turn invocation logs on: they carry the request URL and so the link id. If a different sink is wanted, use a Tail Worker or Logpush job that forwards only objects with an `event` or `alert` field.

- [ ] After deploy, open the Worker's Observability page and confirm one `links.health` object arrives each minute and that no line shows a request URL.
- [ ] Alert on `alert = "free_plan_70"` (one line per metric per UTC day: `requests`, `d1_rows_read`, `d1_rows_written`, `d1_database_bytes`). In Workers Logs, save a query on the field `alert` equal to `free_plan_70`; if the alerting tool is Better Stack, forward the Worker's logs to it (Logpush or OpenTelemetry export, with a filter on the `alert` and `event` fields) and alert on the same field.
- [ ] Alert on `event = "links.health"` with a non-empty `highWater` (a type at 80 % of its quota).
- [ ] **One end-to-end alert proof before public launch.** Temporarily lower `alertPercent` in `WORKERS_FREE_PLAN` (for example to 0.01) in a throwaway deploy, or send enough requests to a non-production deploy, wait one minute, and confirm the `free_plan_70` object reaches the alerting tool and notifies the on-call contact. Revert, redeploy, and record the date and the notification in the launch ticket.

Before email is enabled:

- [ ] An alert on a missing `links.health` line (no line for several minutes) and an alert on any 5xx rate above zero exist and have been shown to fire in a test (for example against a throwaway deploy with an invalid `LINKS_READ_SIGNERS`, which answers 500 and writes no health line), BEFORE email is enabled. A malformed allow-list is noticed through these two alerts, not through a log line from the request handler.

## Plan

- [ ] **Move to Workers Paid before public launch.** The Free limits tracked by the alert (100,000 requests a day; D1 5,000,000 rows read and 100,000 rows written a day; 500 MB database size) are in `WORKERS_FREE_PLAN` with their source and date. After the move, update that table or set `plan` to `null` in `src/worker.ts`.

## Rollback

1. Remove the custom domain from the Worker (traffic to `api.tinycloud.xyz` stops).
2. `npx wrangler rollback` returns the Worker to its previous version, or `npx wrangler delete` removes it.
3. Keep the D1 database: records expire on their own, and nothing else reads it. Drop it after the hold the operator picks.
4. The `share-links` Worker is not touched by this launch.

Details: TC-1737
