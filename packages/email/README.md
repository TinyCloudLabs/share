# `@tinycloud/share-email`

The only server-side Share function: send one owner-node-authorized invitation email.

`POST https://api.share.tinycloud.xyz/v1/email` accepts exactly the node delivery receipt returned by `TinyCloudNode.authorizeShareDeliveryV3`: `{ request, admission, proof }`.

The Worker verifies:

- the v3 envelope's owner signature and complete delegation/root integrity;
- the attested owner Node signature and exact API audience;
- the sender session-key signature;
- equality of recipient, resource, policy/share ID, public fragment-free `?tc2` link, label, share expiry, issued/expiry times, and nonce across the request and admission;
- a maximum five-minute authorization lifetime;
- the public policy-envelope CID and exact-email matcher in the link;
- single-use delivery by reserving the nonce in D1 before calling Resend.

The Worker receives no bearer fragment, envelope key, content key, or document bytes. It exposes no blob, registry, binding, policy, proxy, content, read, or mint route. Email delivery grants no access; the recipient must still satisfy the TinyCloud policy at the owner's node.

Refusals are stable JSON errors: `malformed` (400), `share-url-invalid` (400), `untrusted` (401), `expired` (403), replay/in-flight (409), store/configuration unavailable (503), and provider unavailable (502).
