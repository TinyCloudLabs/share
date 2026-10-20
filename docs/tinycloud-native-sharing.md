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

## Saving a copy

For a markdown, HTML or JSX file the viewer bar offers "Save a copy". Opening a share stays account-free: nothing in the receive path loads or calls OpenKey, and the button is the only thing that can start it.

On the click, Share signs the recipient in with OpenKey (`signInWithManifest` in `src/share/openkey-session.ts`, the same sign-in the library uses). The session holds a manifest that asks only for read, write and list under `files-for-you/v1/`, plus the account-registry permissions the SDK needs for a new account. Share hosts their own `files-for-you` space if it is new and writes the bytes the viewer already holds. A page or component is stored as its source text, never as a page, and keeps its `.html` / `.jsx` name.

- The copy is `files-for-you/v1/<name>`. The name is stored percent-encoded (`q3 report.md` is `q3%20report.md`) because the node refuses a key with a space or a non-ASCII character. Each write is create-only (`If-None-Match: *`); a taken name becomes `<name> (2)`, `<name> (3)`, and so on. An earlier copy is never replaced.
- Only the bytes, name and media type are stored. Nothing about the share (link, id, sender, expiry) is, so the copy outlives the share without naming it: revoking the original does not touch it.
- The session lives in memory for the one call. No key, token or session is written to storage or the console.
- An OpenKey approval is asked for one at a time, for up to 60 seconds. While it is open the bar says "Approve in the OpenKey window to save a copy"; a cancel, a timeout or another failure is a plain message and the viewer stays usable. When it is done the bar says "Saved." with a link to "Open in TinyCloud", and announces it.

`signInWithManifest({ manifest, config, session?, onStatus?, hostSpaces?, guardApproval?, onClient? })` takes any manifest (or a function of the signed-in address) and returns `{ tinycloud, session, spaces }`; the library, Save a copy and an app-install flow differ only in the manifest they pass.
