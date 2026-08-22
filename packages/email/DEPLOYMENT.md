# Deploying `api.share`

This package is an independent Cloudflare Worker; the Share Pages build does not deploy it.

## Resources

- Route: `api.share.tinycloud.xyz/*`.
- D1: `tinycloud-share-email`, migrated with `migrations/0001_deliveries.sql`.
- Secret: `RESEND_API_KEY`.
- Vars: `DELIVERY_AUDIENCE=https://api.share.tinycloud.xyz`, `SHARE_ORIGIN=https://share.tinycloud.xyz`, and a verified `EMAIL_FROM` identity.

There is deliberately no deployment-wide Node key. Each authorization is
joined to the owner-signed v3 envelope and the Node attestation embedded in
that envelope, so owners discovered on different TinyCloud nodes can send.

Deploy deliberately with `npx wrangler deploy --config wrangler.jsonc`. Verify `GET /health/readiness` reports only readiness, an unsigned `POST /v1/email` is refused, and every non-email product route returns 404.

D1 stores only the single-use nonce, share CID, recipient digest, state, provider message ID, and timestamps. It never stores the recipient address, invitation URL, policy envelope, capability, or content.

Rollback with `npx wrangler rollback`. The D1 nonce ledger remains authoritative across rollback so an already-sent authorization cannot send again.
