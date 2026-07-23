# @tinycloud/share-registry

Registry client + local dev registry server for TinyCloud sharing links
(stage 2 of the bearer vertical slice; see
`specs/sharing-viewer-and-registry.md` §6 and `specs/sharing-ux-blueprint.md`
§2.1). Depends on `@tinycloud/share-envelope` for all CID logic — no crypto
or CID code is reimplemented here.

## Client (browser + node)

```ts
import { putBlob, fetchBlob } from "@tinycloud/share-registry";

const { cid, deleteAfter } = await putBlob(
  "http://127.0.0.1:8787",
  sealed.blob,
  new Date(Date.now() + 60 * 60 * 1000), // deleteAfter — required
);
const bytes = await fetchBlob("http://127.0.0.1:8787", cid);
```

- `putBlob` — `POST /blobs` with the raw sealed blob. `deleteAfter` (Date or
  ISO-8601 string) is **required** — the server never defaults to permanent
  retention — and the effective (possibly clamped) value is returned. The
  client recomputes `computeCid(blob)` locally and asserts it equals the
  server's answer; the server's CID is **never trusted**. Blobs over the cap
  (default 64 KiB — envelopes are 1–2 KB) are rejected before any network
  call (`BlobTooLargeError`).
- `fetchBlob` — `GET /ipfs/<cid>?format=raw` with
  `Accept: application/vnd.ipld.raw`. Received bytes are re-verified against
  the CID (`verifyCid`) before being returned; a lying gateway throws
  `CidMismatchError`. Non-2xx and wrong content-type throw
  `RegistryHttpError`. Fail closed — no silent fallbacks.

## Dev server (node-only entry)

```ts
import { createDevRegistry, serveDevRegistry } from "@tinycloud/share-registry/dev-server";

// In-process (tests): a web-standard (Request) => Promise<Response> handler
const { handler, store, sweepExpired } = createDevRegistry({ maxBlobBytes: 64 * 1024 });

// Real listener (dev): node:http wrapper around the same handler
const running = await serveDevRegistry({ port: 8787 });
```

CLI: `npm run -w @tinycloud/share-registry dev-server -- --port 8787`

Endpoints:

- `POST /blobs` (also `PUT`) — create-only upload. Ingestion is atomic per
  spec §6: compute canonical raw CID → assert → store bytes → persist
  retention record (`{ bytes, uploadedAt, deleteAfter }` keyed by CID),
  and only then return `{ cid, deleteAfter }`. Re-uploading identical bytes
  is idempotent (200); an existing CID with different bytes is 409 —
  unreachable honestly, since the CID is derived from the bytes (sha2-256),
  it exists only as a defensive tamper check. The
  `x-delete-after: <ISO-8601>` header is **required** and sets the retention
  expiry, clamped to `maxRetentionSeconds` (default 30 days); missing,
  invalid, or past values are 400.
- `GET /ipfs/<cid>?format=raw` — trustless-gateway shape (see below). 406
  without `?format=raw` or a raw `Accept` header; 404 for unknown or expired
  CIDs. `GET /blobs/<cid>` is a convenience alias.
- `sweepExpired()` — drops expired entries; dev-simulates the production
  `ipfs pin rm` + `repo gc` expiry cron. Expiry is also checked on every GET,
  so a lazy sweep never serves expired bytes.
- **NoFetch posture**: the server only ever serves its local in-memory
  store; it never fetches from any network.

## Trustless-gateway compatibility

`GET /ipfs/<cid>?format=raw` mirrors kubo's **trustless gateway** response
shape: `Content-Type: application/vnd.ipld.raw`, the exact stored block
bytes, and `Cache-Control: public, max-age=…, immutable` with `max-age`
bounded by the retention record's `deleteAfter` (spec §6's edge-cache
semantics — no cache may outlive deletion by more than the remaining
retention window).

Because the client re-verifies every CID locally, the gateway is untrusted
by construction — which is exactly what makes this dev server swappable for
the production single-uploader kubo (`Gateway.NoFetch=true`,
`Gateway.DeserializedResponses=false`, `Routing.Type=none`, spec §6.2) with
**no client change**. The dev server exists so stages 3–4 (viewer,
create-flow) have something to talk to without running kubo.

Remember (blueprint §2.1): the registry stores ciphertext only, and deleting
a registry object is **never** revocation — revocation happens at the node
against the delegation CID.
