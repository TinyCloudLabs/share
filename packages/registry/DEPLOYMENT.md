# Production registry

Deploy from this directory with `npx wrangler deploy --config wrangler.jsonc`. Create the R2 bucket `tinycloud-share-registry` first, then grant the Worker only that bucket. Set `REGISTRY_AUTH_PUBLIC_KEY` to the existing Node/delegation public key. Set `REGISTRY_LINK_UPLOAD_PUBLIC_KEY` to the public half of the persistent key created by the production Share API CVM. The latter accepts only the separate link-only authorization shape, with a short expiry and exact session, ciphertext digest, size, and retention bindings; it cannot authorize bindings or reads. The Worker rejects writes without one of those signed contracts and never accepts trust fixtures. The custom route is `registry.tinycloud.xyz`; it is independent of the marketing Pages project.

The Worker also exposes the private server-to-server `POST
/internal/upload-authorizations` route. It accepts only an Ed25519 signature
from the Share API's dedicated registry-upload key and forwards the exact
consume/reserve operation to the `UploadAuthorization` Durable Object. Keep
`REGISTRY_LINK_UPLOAD_PUBLIC_KEY` equal to that key's public half. The Durable
Object is authoritative for JTI uniqueness and the per-principal twenty-upload
window; a missing binding or invalid signature fails closed. Do not expose this
route through browser CORS or replace the Durable Object with process-local
state.

Do not publish trust-bundle changes until the real Node and issuer keys are live. Verify `GET /ipfs/<cid>?format=raw` returns `application/vnd.ipld.raw` bytes and that overwrite mismatches are rejected.
