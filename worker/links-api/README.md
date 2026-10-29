# links-api

The TinyCloud links API, live at `https://api.tinycloud.xyz`: typed, issuer-signed records that return a random opaque id. A Cloudflare Worker with a D1 adapter, and a self-host build on one SQLite file. Both run the same service code over one storage interface.

Contract: `docs/specs/short-links-api-contract.md` in tinycloud-dev (sections 1 to 10 and Appendix B).

## Live state

- Worker `links-api`, version `bba05bcd` at launch, at `https://api.tinycloud.xyz`. The hostname is attached to the Worker in Cloudflare; `wrangler.toml` declares no route or custom domain.
- D1 database `links-api`, id `c26a26cc-7595-42a4-95ae-0f9aec08a228`, with `migrations/0001_init.sql` applied. The id is in `wrangler.toml`.
- With `LINKS_READ_SIGNERS` unset, the Worker accepts no signer on the authenticated read path, so every read counts against the per-address read limit. The allow-list is set when a node signer is registered (contract §4.11).
- The launch checklist is `LAUNCH-CHECKLIST.md`; the live smoke it names passed against the API.

## Routes

| Method and path | Result |
| --- | --- |
| `POST /v1/links` | `201 {"id","expiresAt"}`. Body `{header, signature?, body}`; `signature` is absent when the request carries `Authorization: Bearer tlk_<keyId>_<secret>` (API key, `openkey-login` only). |
| `GET /v1/links/{id}` | `200` raw sealed bytes; the signed record is in `X-Link-Record`. `openkey-login` ids answer the uniform `404`. May carry `TinyCloud-Read-Auth` (see "Authenticated node read"). |
| `POST /v1/links/{id}/take` | `200` as `GET`, once, for `openkey-login` only; the uniform `404` for every other type. |
| `POST /v1/links/{id}/delete` | `204`. Body `{request, signature?}`; only the issuer removes a record. |

Errors are `{"error": "<code>"}` with the statuses of contract 4.8. Unknown, expired, deleted, malformed and already-read ids answer one `404`.

Create and delete request bodies must be JSON objects in which no object, at any depth, repeats a key. Keys are compared after unescaping, so `"a"` and `"\u0061"` are the same key. A body that repeats a key is refused as `400 invalid_request` (`src/json-strict.ts`, one pass over the text: linear time, no recursion).

## Limits

- One body limit for every type: `MAX_LINK_BODY_BYTES = 65536` (sealed bytes) in `src/config.ts`. The HTTP request cap is derived from it (`ceil(MAX_LINK_BODY_BYTES * 4 / 3) + 3072` = 90,454).
- Lives, quotas, rate limits, the per-address live cap and the type reserve are the tables in `src/config.ts`.
- `openkey-approval-request` v1 is signed-only (Ed25519 `did:key`), with a maximum request life of 86,400 seconds. The SDK's default is 3,600 seconds; the Worker requires explicit signed `issuedAt` and `expiresAt` and never supplies or changes them. `audience` is this API instance's configured origin, not OpenKey.
- Approval requests use repeatable, non-consuming `GET /v1/links/{id}`. Prefetch does not consume them; `/take` returns `404` without removing them. Reads at or after request expiry return the uniform `404`. Existing `openkey-login` remains 600 seconds maximum and explicit single-use `/take`.
- The returned opaque `id` is the request id. `bodyCid` hashes the actual sealed bytes; the Worker stores and returns those bytes and the signed header without parsing request plaintext. Consumers must verify the signed record, CID, AEAD and sealed issuer/target bindings. Result discovery, approval-time expiry checks, result retention and durable-save-before-ACK belong to OpenKey/CLI, not this request store.
- Approval-request admission uses the existing per-type quota mechanism: 4,000 live rows and 134,217,728 live sealed bytes, with unchanged address caps, reserve, nonce and rate limits. This request quota and request lifetime do not set grant lifetime or approved-result retention.
- Browser origins for `POST`: `LINKS_CORS_ORIGINS` (default `https://share.tinycloud.xyz`); `GET` answers any origin without credentials.

## Configuration

| Variable | Meaning |
| --- | --- |
| `ADDRESS_SALT` | Required, 16 or more characters. Salts the address hashes stored with records and counters. Set as a secret. |
| `LINKS_AUDIENCE` | The origin this instance serves (default `https://api.tinycloud.xyz`). |
| `LINKS_CORS_ORIGINS`, `LINKS_TAKE_ORIGINS` | Comma lists of browser origins for create and delete, and for take (default none). |
| `KILL_CREATE`, `KILL_READ`, `KILL_TAKE`, `KILL_DELETE` | `1` answers that operation `503 capacity`. |
| `CLIENT_ADDRESS_HEADER` | Header that carries the client address (default `CF-Connecting-IP`). |
| `LINKS_READ_SIGNERS` | JSON list `[{"label":"service:node","did":"did:key:z6Mk..."}]`: the keys whose signed reads use the label's own bucket. At most two keys per label; validated at load (an invalid list stops the service from serving). Default: none. The production DID is configuration and is not kept in this repository. |
| `LINKS_READ_AUTH_LIMIT` | Reads a minute per label for those keys (default 6,000; a positive integer). |

The client address maps to a bucket: IPv4 the address, IPv4-mapped IPv6 its IPv4 address, IPv6 the /64 for rate limits and the /48 for the live cap, in RFC 5952 form. An address that does not parse falls into the one bucket `unparseable`.

## Authenticated node read

`GET /v1/links/{id}` may carry `TinyCloud-Read-Auth: <value>`: unpadded base64url of the canonical JSON (RFC 8785) `{"issuedAt","signature","signerDid"}`, at most 512 bytes. The signature is Ed25519 over `SHA-256(utf8("xyz.tinycloud.links/read-auth/v1\0") || utf8(JCS({audience, issuedAt, method:"GET", path:"/v1/links/<id>", signerDid})))`, verified with the strict rule of the contract (section 2.5). The Worker builds `method`, `path` and `audience` from the request it received and from its configuration, so the header does not carry them. The header is read only on `GET /v1/links/{id}` with a lower-case 26-character id and no query string.

A read is served from the label's own bucket (`LINKS_READ_AUTH_LIMIT`, default 6,000 a minute; the per-address read limit is not used for it) when the signer is on `LINKS_READ_SIGNERS` and `issuedAt` is within 120 seconds of the service clock (inclusive). Any other read, with or without the header, is an ordinary read under the per-address limit and gets the same status, body and headers: the response never says whether the header was recognised. The only operator-visible trace is `reads.authenticated` in the `links.health` line. Every response carries a `Date` header from the service clock.

Rotation: the list holds up to two keys for a label. Add the new key (two keys listed), deploy the node with the new key, then remove the old key from the list. A removed key is an ordinary reader from the next request. A key used in a test must not be listed in production.

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
- `test/approval-request.test.ts` exercises signed approval-request creation, repeatable prefetch/GET, exact expiry boundaries, service-mode refusal, issuer/signature/CID/header checks, replay, deletion and existing admission limits with the SQLite and local D1 adapters.
- Reader-side vector groups (`records`, `resolve`, `links`, `linkChoice`, `deliveryAdmission`) belong to the viewer, CLI, node and witness. Only the six `records` body-size boundary vectors (at the limit and one byte over it, for each type) are run here, against the checks the service shares with readers.
- `.github/workflows/links-api.yml` runs the Worker typecheck and full suite on scoped feature-branch pushes and pull requests, using only isolated local SQLite/D1 state. Opening a PR also triggers the separate existing sender sign-in workflow, which uses production accounts; a Worker-only feature push does not trigger that workflow.

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

Details: TC-1737, TC-2212
