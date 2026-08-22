# TinyCloud-native sharing

This document is the cutover architecture. Older Share registry/blob and claim-link designs are retired and their links are intentionally unsupported.

## Data and authority flow

1. The sender signs in to TinyCloud through OpenKey.
2. Share writes the selected bytes to the sender's TinyCloud applications space. Addressed content is encrypted client-side before the KV write.
3. The public SDK asks TinyCloud for exactly one delegation or policy over that owner-space resource.
4. Share constructs one of two links:
   - bearer: `https://share.tinycloud.xyz/viewer#tc1=<opaque TinyCloud delegation>`;
   - addressed: `https://share.tinycloud.xyz/viewer?tc2=<canonical signed Policy/v3 envelope>`.
5. The recipient resolves the owner's node through `registry.tinycloud.xyz`, proves any required DID or email policy, and invokes that node.
6. The owner node reads and decrypts only after delegation or policy enforcement. Revoking the delegation makes later invocation fail.

The addressed envelope is public authorization metadata. It contains no content decryption key. The encrypted document never passes through Share or the email API.

## Service boundaries

| Service | Required responsibility | Explicitly forbidden |
| --- | --- | --- |
| Share Pages | Static sender/viewer UX and local link parsing | Content storage, capability storage, signing proxy, policy resolution |
| Owner TinyCloud node | Store content, create/register delegation policy, authorize invocation and optional email intent, enforce revocation | Delegating authority to Share infrastructure |
| Registry | DID-to-node location discovery with public GET/OPTIONS CORS | Share blobs, policy envelopes, bindings, capabilities |
| `api.share` | Verify an exact node/sender delivery receipt, enforce single-use JTI, send email | Mint/read/store/proxy content or capabilities; receive bearer fragments |
| OpenCredentials witness | Issue/prove the recipient credential used by policy admission | Decide TinyCloud resource access |

## Email intent

The sender submits the public `?tc2` URL to the owner node with the exact recipient, resource path, document label, and a delivery expiry no more than five minutes away. The node verifies the registered Policy/v3 envelope and active roots, binds those fields into a signed admission for audience `https://api.share.tinycloud.xyz`, and returns it to the sender session. The sender signs the invitation request. The email API verifies both signatures and the URL-to-envelope CID, reserves the nonce in D1, and sends the exact URL once.

No fragment secret is present in the URL or request body.
