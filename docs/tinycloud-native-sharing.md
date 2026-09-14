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
6. The owner node authorizes the encrypted-KV and decrypt capabilities. The browser verifies the signed ciphertext digest, invokes the generic decrypt capability, and decrypts/renders locally. Revocation makes later invocation fail.

The addressed envelope is public authorization metadata. It contains no content decryption key. The encrypted document never passes through Share or the email API.

## Service boundaries

| Service | Required responsibility | Explicitly forbidden |
| --- | --- | --- |
| Share Pages | Static sender/viewer UX and local link parsing | Content storage, capability storage, signing proxy, policy resolution |
| Owner TinyCloud node | Store content, create/register delegation policy, authorize invocation and optional email intent, enforce revocation | Delegating authority to Share infrastructure |
| Registry | DID-to-node location discovery with public GET/OPTIONS CORS | Share blobs, policy envelopes, bindings, capabilities |
| OpenCredentials (`email.tinycloud.xyz`) | Send a receipt-bound invitation and issue/prove the recipient credential used by policy admission | Decide TinyCloud resource access, read/proxy content, or hold Share authority |

## Email intent

The sender submits the public `?tc2` URL to the owner node with the exact recipient, resource path, document label, and a delivery expiry no more than five minutes away. The node returns a receipt bound to the registered Policy/v3 envelope and active roots for audience `https://email.tinycloud.xyz`. Share forwards that receipt unchanged to OpenCredentials' deployed generic `/v1/email` endpoint, which sends the exact URL once.

No fragment secret is present in the URL or request body.
