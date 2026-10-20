# TinyCloud-native sharing

This document is the cutover architecture. Older Share registry/blob and claim-link designs are retired and their links are intentionally unsupported.

## Data and authority flow

1. The sender signs in to TinyCloud through OpenKey.
2. Share writes the selected bytes to the sender's TinyCloud applications space. Addressed content is encrypted client-side before the KV write.
3. The public SDK asks TinyCloud for exactly one delegation or policy over that owner-space resource.
4. Share constructs one of two links:
   - bearer: `https://share.tinycloud.xyz/viewer#tc1=<opaque TinyCloud delegation>`;
   - addressed: `https://share.tinycloud.xyz/s/inline#v=2&p=<sealed Policy/v3 envelope and local key>`.
5. The recipient resolves the owner's node through `registry.tinycloud.xyz`, proves any required DID or email policy, and invokes that node.
   For an addressed link the page first asks the owner's node whether the share was revoked or has expired (the node's public status route for the envelope's two policy roots). If so, it says so and sends nothing: no key is created and no code is requested. If the node cannot be reached or answers anything else, it carries on as before and the node's own decision applies. The check runs again after the recipient clicks "Email me a code". A share whose content object was deleted is only visible after sign-in, so the page still offers a code for it.
6. The owner node authorizes the encrypted-KV and decrypt capabilities. The browser verifies the signed ciphertext digest, invokes the generic decrypt capability, and decrypts/renders locally. Revocation makes later invocation fail.

The addressed envelope is authorization metadata sealed by the sender SDK. Its sealed bytes and key stay in the URL fragment, so they never appear in the browser's HTTP request. The encrypted document never passes through Share or OpenCredentials.

## Service boundaries

| Service | Required responsibility | Explicitly forbidden |
| --- | --- | --- |
| Share Pages | Static sender/viewer UX and local link parsing | Content storage, capability storage, signing proxy, policy resolution |
| Owner TinyCloud node | Store content, create/register delegation policy, authorize invocation and optional email intent, enforce revocation | Delegating authority to Share infrastructure |
| Registry | DID-to-node location discovery with public GET/OPTIONS CORS | Share blobs, policy envelopes, bindings, capabilities |
| OpenCredentials (`witness.credentials.org`) | Send a receipt-bound invitation and issue/prove the recipient credential used by policy admission | Decide TinyCloud resource access, read/proxy content, or hold Share authority |

## Email intent

The sender submits the addressed URL to the owner node with the exact recipient, resource path, document label, and a delivery expiry no more than five minutes away. The node returns a receipt bound to the registered Policy/v3 envelope and active roots for audience `https://witness.credentials.org`. Share forwards that receipt unchanged to OpenCredentials' deployed generic `/v1/credential-invitations` endpoint, which sends the exact URL once.

The exact signed delivery receipt necessarily carries the complete invitation to OpenCredentials so it can send that link. The browser captures and scrubs the fragment synchronously before imports or network work; Share, Registry, and the owner's node expose no invitation-blob retrieval service.

## Revoking a share

Revoke is in the library ("Shared by me"). The share stays active until the owner's node confirms the revocation: the row says "Revoked" only after that, and a failure or a cancel leaves the share active with Revoke available again.

While the page that created an email, domain or DID share is still signed in, revoking needs no approval. In a later sign-in (a reload, a new day, another device) Share first asks the owner's node whether the share is one of this account's own, then asks for one approval in the OpenKey window and revokes only that share's delegation. Once revoked, the node refuses the recipient's later reads and anything delegated from that share, and leaves the sender's other shares and own access alone. Link-only shares ask for the same one approval.

The approval is good for 60 seconds; if it is not completed in that time Share stops waiting. If the approval times out, the share may still have been revoked: check the status after a moment; trying again will confirm it without a new approval if it was.

While Share waits for the OpenKey approval (creating a share or revoking one), the page says "Approve in the OpenKey window", offers Cancel (it closes the OpenKey window; the action can be tried again), and says so if the wait runs long. The hint disappears the moment the approval closes. After a cancel or a timeout no link was created and nothing was revoked.

Revoking stops access; it does not delete anything. The encrypted copy stays in the owner's TinyCloud until the owner deletes it, because Share's session holds no delete grant. Anyone who already downloaded or copied the content keeps their copy. A link can be revoked by anyone who holds it, so the confirmation says so for link shares.

The library shows what the owner's node says about each share, not only what this browser saved: a share revoked or expired elsewhere (the account site, the CLI) is shown as Revoked or Expired when the library loads, when "Check status" is pressed and when the tab is focused again. Share never shows a status as confirmed when the node could not be asked; it says statuses may be out of date.

"Sign out" in the bar above every screen ends the OpenKey sign-in on this device and clears Share's session in the tab. Shares stay active; nothing is revoked or deleted.
