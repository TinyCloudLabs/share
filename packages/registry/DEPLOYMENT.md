# Production registry

Deploy from this directory with `npx wrangler deploy --config wrangler.jsonc`. Create the R2 bucket `tinycloud-share-registry` first, then grant the Worker only that bucket. Set `REGISTRY_AUTH_PUBLIC_KEY` to the existing Node/delegation public key. Set `REGISTRY_LINK_UPLOAD_PUBLIC_KEY` to the public half of the persistent key created by the production Share API CVM. The latter accepts only the separate link-only authorization shape, with a short expiry and exact session, ciphertext digest, size, and retention bindings; it cannot authorize bindings or reads. The Worker rejects writes without one of those signed contracts and never accepts trust fixtures. The custom route is `registry.tinycloud.xyz`; it is independent of the marketing Pages project.

Do not publish trust-bundle changes until the real Node and issuer keys are live. Verify `GET /ipfs/<cid>?format=raw` returns `application/vnd.ipld.raw` bytes and that overwrite mismatches are rejected.
