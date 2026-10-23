# links-api launch checklist (operator)

Nothing below has been done. Every name is PLANNED until the operator creates it. Order follows contract 7.9: the API goes first.

## Before create

- [ ] The vector copy and its pin match the final contract (`test/vectors/short-links-api-vectors.json`, `VECTORS_SHA256` in `test/support/vectors.ts`); `npm run vectors` passes.
- [ ] `npm ci`, `npm run typecheck` and `npm test` pass at the commit to deploy.
- [ ] Approval for the custom domain and the Cloudflare plan is recorded.

## Create and deploy

1. **D1 database.** Create it (PLANNED name `links-api`); put its id in `wrangler.toml` (`database_id`).
2. **Migration.** `npx wrangler d1 migrations apply links-api --remote` (applies `migrations/0001_init.sql`).
3. **Secret and variables.** `npx wrangler secret put ADDRESS_SALT` (16 or more random characters). Check `LINKS_AUDIENCE` (`https://api.tinycloud.xyz`) and `LINKS_CORS_ORIGINS` (`https://share.tinycloud.xyz`) in `wrangler.toml`.
4. **OpenKey API key.** Generate 32 random bytes, base64url, as the secret; store only `base64url(SHA-256(secret))`. Insert the row (`key_id` is 8 alphanumeric characters):
   `INSERT INTO api_keys (key_id, service, allowed_types, secret_sha256, created_at) VALUES ('<keyId>', 'openkey', '["openkey-login"]', '<hash>', <epoch seconds>);`
   Give OpenKey `tlk_<keyId>_<secret>` out of band. Rotation: add the second key, deploy it to OpenKey, then `UPDATE api_keys SET revoked_at = <epoch seconds> WHERE key_id = '<old>';`.
5. **Worker.** `npx wrangler deploy` (the cron trigger `* * * * *` runs the sweep and the health line every minute).
6. **Custom domain and DNS.** Attach `api.tinycloud.xyz` to the Worker as a custom domain (this creates the DNS record). No other route is declared.
7. **Smoke.** `node scripts/local-smoke.ts https://api.tinycloud.xyz` (creates, reads, takes and deletes test records that expire on their own).

## Alerts

- [ ] Log alert on the line `"alert":"free_plan_70"` (one line per metric per UTC day: `requests`, `d1_rows_read`, `d1_rows_written`, `d1_database_bytes`).
- [ ] Log alert on `"event":"links.health"` with a non-empty `highWater` (a type at 80 % of its quota).
- [ ] Check that the `links.health` line arrives every minute.

## Plan

- [ ] **Move to Workers Paid before public launch.** The Free limits tracked by the alert (100,000 requests a day; D1 5,000,000 rows read and 100,000 rows written a day; 500 MB database size) are in `WORKERS_FREE_PLAN` with their source and date. After the move, update that table or set `plan` to `null` in `src/worker.ts`.

## Rollback

1. Remove the custom domain from the Worker (traffic to `api.tinycloud.xyz` stops).
2. `npx wrangler rollback` returns the Worker to its previous version, or `npx wrangler delete` removes it.
3. Keep the D1 database: records expire on their own, and nothing else reads it. Drop it after the hold the operator picks.
4. The `share-links` Worker is not touched by this launch.

Details: TC-1737
