# `@tinycloud/share-email`

The send half of addressed sharing, as a Cloudflare Worker. Sibling of
`packages/registry`: same account, same deploy path, same test shape.

```
POST https://email.tinycloud.xyz/share/v2
{ "authorization": { … }, "proof": { "alg": "EdDSA", "kid": "…", "signature": "…" }, "shareUrl": "https://share.tinycloud.xyz/s/<cid>#k=…" }
```

That body is exactly the `ShareDeliveryAuthorizationReceipt` that
`TinyCloudNode.authorizeShareDelivery` already returns (node-sdk 2.10.0),
plus the share URL — the same JSON `src/share/main.ts` POSTs today.

## Why there is no database to provision

Addressed sharing stalled on `share-email` needing a durable PostgreSQL that
does not exist anywhere in the org's infrastructure. A Worker does not need
one. The only durable state the send half has is "did I already send this",
which is one primary key in D1.

## Authorization

**This is not an open relay.** Being able to POST here grants nothing. The
Worker sends only when the Node has signed the delivery, and re-derives every
binding from operator configuration:

| Bound thing | Checked against |
| --- | --- |
| The Node's signature over `domain ‖ jcs(authorization)` | `NODE_INVITATION_KID` + `NODE_INVITATION_PUBLIC_KEY` |
| `targetOrigin` / `nodeAudience` | `NODE_ORIGIN` |
| `openCredentialsAudience` | `DELIVERY_AUDIENCE` |
| `returnOrigin`, and the whole share-URL grammar | `SHARE_ORIGIN` |
| `deliveryEmail` | the share's own signed `recipientMatcher` |
| `expiresAt` (≤ 5 minutes), `shareExpiresAt` | wall clock |
| `idempotencyKey` (= the Node's `jti`) | the D1 ledger |

The signature is verified **first**. Only once the Node has vouched for the
bytes are the remaining refusals distinguishable — answering "your audience is
wrong" to an unsigned blob would make this endpoint a configuration oracle.
Failures that would reveal whether a key is enrolled all collapse into one
generic `untrusted`, the same way the OpenCredentials witness's `UntrustedNode`
does.

There is **no fallback**. No key baked in, no "accept anything when unset".
Production currently publishes a development fixture as
`nodeInvitationPublicKey`, and the route that publishes the real one
(`GET /.well-known/tinycloud/node-keys`) is merged but not deployed
(TC-359 / TC-369) — so the trusted key is configuration, and an unset or
non-matching key refuses to send.

## Refusal reasons

Every refusal is `{ "error": "<reason>" }`:

| Reason | Status | Meaning |
| --- | --- | --- |
| `configuration-unavailable` | 503 | A secret, var or binding is missing. Nothing was read or sent. |
| `malformed` | 400 | Not the exact `{ authorization, proof, shareUrl }` shape, or a field failed its own grammar. |
| `untrusted` | 401 | Not signed by the enrolled Node key, or an audience/origin does not match configuration. |
| `expired` | 403 | The authorization, or the share itself, is no longer live. |
| `share-url-invalid` | 400 | Not `https://<share origin>/s/<cid>#k=<43 chars>`. |
| `replayed` | 409 | This authorization was already used. |
| `in-flight` | 409 | A send for this authorization is running now. |
| `store-unavailable` | 503 | D1 could not be read or written. No email was sent. |
| `provider-unavailable` | 502 | Resend rejected or could not be reached. |
| `origin-not-allowed` | 403 | A browser on some other site tried to drive it. |

## Secrets

The share URL carries the AEAD key in its fragment, so it is a secret. This
package **logs nothing at all** — there is no `console` call in `src/`, and a
test asserts it stays that way. The D1 row keeps a SHA-256 digest of the
recipient address, never the address, the URL or the document name. Resend
response bodies are never surfaced: they can echo recipient PII, so only the
numeric status escapes.

## Out of scope

The **claim ceremony** — proving the recipient controls the mailbox before
access is granted — is not here. Exact-email delivery is owned by
OpenCredentials, which receives the Node authorization plus the `k`-only base
URL and mints the one-use invitation material before sending. This legacy
Worker refuses exact-email authorizations so it cannot deliver an unusable
`k`-only link.

See `DEPLOYMENT.md` for what provisioning it needs.
