# links-api

The TinyCloud links API (`api.tinycloud.xyz`, PLANNED): typed, issuer-signed records that return a random opaque id. A Cloudflare Worker with a D1 adapter, and a self-host build on one SQLite file. Both run the same service code over one storage interface.

Contract: `docs/specs/short-links-api-contract.md` in tinycloud-dev (sections 1 to 10 and Appendix B). Nothing in this directory is deployed, created or bound; `wrangler.toml` marks every name PLANNED.

## Routes

| Method and path | Result |
| --- | --- |
| `POST /v1/links` | `201 {"id","expiresAt"}`. Body `{header, signature?, body}`; `signature` is absent when the request carries `Authorization: Bearer tlk_<keyId>_<secret>` (API key, `openkey-login` only). |
| `GET /v1/links/{id}` | `200` raw sealed bytes; the signed record is in `X-Link-Record`. `openkey-login` ids answer the uniform `404`. |
| `POST /v1/links/{id}/take` | `200` as `GET`, once, for `openkey-login` only; the uniform `404` for every other type. |
| `POST /v1/links/{id}/delete` | `204`. Body `{request, signature?}`; only the issuer removes a record. |

Errors are `{"error": "<code>"}` with the statuses of contract 4.8. Unknown, expired, deleted, malformed and already-read ids answer one `404`.

## Limits

- One body limit for every type: `MAX_LINK_BODY_BYTES = 65536` (sealed bytes) in `src/config.ts`. The HTTP request cap is derived from it (`ceil(MAX_LINK_BODY_BYTES * 4 / 3) + 3072` = 90,454).
- Lives, quotas, rate limits, the per-address live cap and the type reserve are the tables in `src/config.ts`.
- Browser origins for `POST`: `LINKS_CORS_ORIGINS` (default `https://share.tinycloud.xyz`); `GET` answers any origin without credentials.

## Configuration

| Variable | Meaning |
| --- | --- |
| `ADDRESS_SALT` | Required, 16 or more characters. Salts the address hashes stored with records and counters. Set as a secret. |
| `LINKS_AUDIENCE` | The origin this instance serves (default `https://api.tinycloud.xyz`). |
| `LINKS_CORS_ORIGINS`, `LINKS_TAKE_ORIGINS` | Comma lists of browser origins for create and delete, and for take (default none). |
| `KILL_CREATE`, `KILL_READ`, `KILL_TAKE`, `KILL_DELETE` | `1` answers that operation `503 capacity`. |
| `CLIENT_ADDRESS_HEADER` | Header that carries the client address (default `CF-Connecting-IP`). |

The client address maps to a bucket: IPv4 the address, IPv4-mapped IPv6 its IPv4 address, IPv6 the /64 for rate limits and the /48 for the live cap, in RFC 5952 form. An address that does not parse falls into the one bucket `unparseable`.

## Storage

`migrations/0001_init.sql` creates `links`, `rl` (fixed-window counters), `nonces`, `blocked`, `api_keys`, `metrics` and `usage_daily`. `src/storage.ts` is the interface; `src/sql-storage.ts` implements it over a small SQL driver, and `src/d1-driver.ts` and `src/sqlite-driver.ts` are the two adapters. The admission checks and the insert are one statement.

## Health and the Free plan alert

The scheduled run (every 60 s; a timer in the self-host build) sweeps, folds the window's counters into the day's totals, and logs one `links.health` line (counts only). The live row and byte totals scan every live row, so they are computed every 5th minute on Cloudflare (`live` and `highWater` are `null` in the other runs) and every minute in the self-host build.

The Worker build compares the day's usage with the Workers Free limits in `WORKERS_FREE_PLAN` (`src/config.ts`, one table with the source URL of each value and the date read) and logs one line per metric per UTC day when a metric reaches 70 %:

```
{"alert":"free_plan_70","metric":"requests","pct":70,"day":"2026-10-24"}
```

`metric` is `requests`, `d1_rows_read`, `d1_rows_written` or `d1_database_bytes`. The `usage` field of `links.health` carries `used`, `limit` and `pct` for each. Every request is counted once, at the top of the handler (including preflights, unknown routes and 404s); D1 rows read and written and the database size come from the `meta` of each D1 result. The self-host build keeps the same counters, reports `limit` and `pct` as `null`, and never alerts.

### Where the lines go

`wrangler.toml` turns Workers Logs on with invocation logs off:

```
[observability]
enabled = true
head_sampling_rate = 1

[observability.logs]
invocation_logs = false
```

Keys as documented at https://developers.cloudflare.com/workers/observability/logs/workers-logs/ (page dated 2026-10-12, read 2026-10-23). Invocation logs would carry `<Method> <URL>` for each request, and the path holds the link id, so they stay off. The request handler writes no console line; the only console output is the scheduled run's `links.health` and `free_plan_70` objects, which Workers Logs indexes by field. `test/observability.test.ts` sends requests with a sentinel id, query and path (and a failing database and a missing salt) through the Worker entry, runs the scheduled handler, and asserts that no console line contains any of them. Workers Free keeps 200,000 log events a day for 3 days; the scheduled run writes about 1,440 a day.

In the local run of `scripts/local-smoke.ts` the counters reported D1 rows written and read per request; read the figures from the `usage` field of the health line.

## Tests

```
npm ci
npm run typecheck
npm test                 # unit, storage conformance 1 to 21 on both adapters, vectors, sentinel, self-host
npm run vectors          # every service-level vector on both adapters; checks the pinned SHA-256
```

- `test/conformance.test.ts` runs storage conformance 1 to 21 against the D1 adapter (a local D1 from miniflare) and the SQLite adapter. Conformance 22 is `test/vectors.test.ts`.
- `test/vectors/short-links-api-vectors.json` is a byte-identical copy of the contract's vector file; its SHA-256 is pinned in `test/support/vectors.ts` (`VECTORS_SHA256`). Updating the file is a change of that file and that one line.
- Reader-side vector groups (`records`, `resolve`, `links`, `linkChoice`, `deliveryAdmission`) belong to the viewer, CLI, node and witness. Only the six `records` body-size boundary vectors (at the limit and one byte over it, for each type) are run here, against the checks the service shares with readers.

## Local run (no deploy)

```
npx wrangler d1 migrations apply links-api --local --persist-to <private dir>
npx wrangler dev --local --port 8799 --persist-to <private dir> --var ADDRESS_SALT:<16+ characters> --test-scheduled
node scripts/local-smoke.ts http://127.0.0.1:8799
curl 'http://127.0.0.1:8799/__scheduled?cron=*+*+*+*+*'
```

Both wrangler commands stay on the local D1; no account, route or database is touched.

## Self-host

```
LINKS_DB_PATH=links.sqlite ADDRESS_SALT=<16+ characters> node src/selfhost.ts
```

Node 22.18 or newer. The server sets the client address from the socket; behind a proxy, set `CLIENT_ADDRESS_HEADER` to the header the proxy sets.

Details: TC-1737
