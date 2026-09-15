# TC-500 production-origin gate

This directory is intentionally separate from the regular test command. The
gate creates real owner data and mails only a disposable `@mailinator.com`
recipient, so it must be explicitly enabled after the Node and OpenCredentials
production deployments are green.

`candidate-server.mjs` serves the current `dist/` over local TLS. A dedicated
Chrome instance maps only `share.tinycloud.xyz` to that local listener. The URL
and Origin the browser presents remain `https://share.tinycloud.xyz`; the
owner node, `witness.credentials.org`, and `registry.tinycloud.xyz` are never
proxied. It parses the candidate's copied `public/_headers` and applies the
same CSP, Trusted Types, sandbox, cache, referrer, and MIME-sniffing contract
as production. It refuses every Host other than `share.tinycloud.xyz` and has
no upstream fallback.

That last point is deliberate: the TC-500 Share application has no
same-origin auth, registry, blob, credential, or data-plane endpoint. Adding a
proxy to an obsolete `/share/*` or generic API route would hide a regression.

The final runner must capture, from one new recipient browser context:

- no OpenKey request before render;
- OpenCredentials `/v1/acquisitions`, Node Policy/v3, generic `/delegate`,
  and generic `/invoke` requests;
- ciphertext from the owner's KV only, before local decrypt/render; and
- exact non-UTF-8 input bytes plus the denial/revocation/tamper cases.

The gate cryptographically verifies the owner's signed Location Registry
record before launching Chrome and then requires the browser's Policy/v3,
`/delegate`, and `/invoke` traffic to use that same discovered Node origin.
Credential acquisition is pinned exactly to `https://witness.credentials.org`.
Browser message text and request bodies are never emitted: the report contains
only fixed route labels, origin bindings, counts, and the expected byte digest.

Run only with a disposable Mailinator inbox and an explicitly provisioned
owner account. Never point this at a real recipient or alter system DNS; use
Chrome's per-process host resolver rule and dispose of the browser profile and
temporary certificate after the run.

`recipient-gate.mjs` is the executable recipient half. It is deliberately
opt-in and requires the actual mailed invitation, its Mailinator OTP, and the
sender's original non-UTF-8 file. It verifies the downloaded local bytes and
the required OpenCredentials/Policy-v3/delegate/invoke trace, while refusing
OpenKey or legacy Share traffic. It does not create an invitation itself.
