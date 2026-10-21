# share-links Worker

Cloudflare Worker that stores short-lived sealed blobs for share links (TC-1737). The server stores and returns ciphertext only; the decryption key never reaches the server.

## API

Base path: `/api/share-links` on `share.tinycloud.xyz`.

| Method | Path | Success | Notes |
| --- | --- | --- | --- |
| POST | `/api/share-links` | 201 `{id, cid, deleteToken}` | Body `{ciphertext, expiresAt}`. `ciphertext` is unpadded base64url, 1..131072 decoded bytes. `expiresAt` is canonical UTC with milliseconds and `Z`. TTL 120 s to 400 days. |
| GET | `/api/share-links/<id>` | 200 raw bytes | `application/octet-stream`, `Content-Disposition: attachment; filename="share.bin"`, `X-Share-Cid`, `X-Share-Expires`, `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, `Content-Security-Policy: default-src 'none'; sandbox`, `Cross-Origin-Resource-Policy: same-origin`. No CORS headers. |
| DELETE | `/api/share-links/<id>` | 204 | Requires `Authorization: Bearer <deleteToken>`. |

Errors:

- 400 `{"error":"invalid"}` for any malformed create body.
- 404 `{"error":"not_found"}` for unknown, expired, deleted, malformed, or wrong-token requests. These are indistinguishable by design.
- 429 `{"error":"rate_limited"}` with `Retry-After`.
- 503 `{"error":"capacity"}` with `Retry-After: 3600` when the global cap is reached.

## Limits

- Create: 10 per minute and 200 per day per client.
- Read: 120 per minute per client.
- Global: 20,000 live rows and 2 GiB of live ciphertext.
- Client identity is `CF-Connecting-IP`, hashed with a salt before storage.
- Create request bodies are capped at 184,320 bytes while reading, before JSON parsing.

## Storage

D1 database with two tables (`migrations/0001_init.sql`):

- `links`: id, ciphertext, cid, expires_at, delete_hash, size, created_at, deleted_at. Delete sets `deleted_at` and clears the ciphertext to a tombstone.
- `rl`: per-client rate-limit counters.

The delete token is stored only as `base64url(sha256(token))`.

## Cleanup

An hourly cron (`0 * * * *`) deletes rows with `expires_at < now` and rate-limit rows with `exp < now`.

## Operations

Read-only capacity check (the alert reads these names; the same figures the create cap uses):

```
SELECT count(*), coalesce(sum(size), 0) FROM links WHERE deleted_at IS NULL AND expires_at > :now;
```

Request bodies are read with a running byte cap (184,320 bytes) and rejected before the full body is buffered.

## Layout

- `src/index.ts`: Worker entry (fetch and scheduled).
- `src/app.ts`: routing and handlers.
- `src/validate.ts`: create-body parsing and limits.
- `src/encoding.ts`: base64url, base32, CID, id and token generation, hashing.
- `src/store.ts`: D1 reads, inserts with caps, deletes, cleanup.
- `src/ratelimit.ts`: fixed-window counters.
- `src/responses.ts`: response helpers and common headers.
- `src/d1.ts`: D1 binding types.
- `smoke.sh`: post-deploy smoke check (POST, GET headers and bytes, DELETE, uniform 404).

## Tests

```
cd worker/share-links
../../node_modules/.bin/vitest run test/encoding.test.ts
../../node_modules/.bin/vitest run test/validate.test.ts
../../node_modules/.bin/vitest run test/app.test.ts
../../node_modules/.bin/tsc --noEmit -p tsconfig.json
```

Tests run against an in-memory SQLite database (`node:sqlite`, `test/helpers/d1.ts`) that applies the production migration. They do not exercise Workers runtime or real D1.

`test/encoding.test.ts` checks CIDs against the shared vector file at `~/scratch/artifacts/ship/shortlink-vectors.json`.

## Deploy order

1. Apply the migration to the target D1 database before deploying the Worker.
2. Deploy the Worker with `wrangler deploy`.
3. Confirm the route `share.tinycloud.xyz/api/share-links/*` and the cron trigger in the Cloudflare dashboard.
4. Run the smoke script: `./smoke.sh https://share.tinycloud.xyz`. It creates one link with a one-hour TTL, checks the GET headers and bytes, checks a wrong-token DELETE and the uniform 404, deletes the link, and checks the 404 after delete.

Steps 1 to 4 are performed by the release owner. Nothing here deploys automatically.
