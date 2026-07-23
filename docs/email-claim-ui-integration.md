# Exact-email UI integration boundary

The `/share.html` sender surface and `/s/<cid>` recipient surface contain the
production client state machine. They do not ship a simulated sender identity,
registry uploader, mail provider, credential issuer, or policy authority.

The remaining cross-repository seam is intentionally typed:

- Each authenticated host capability contains one exact, already-authorized
  content source and its matching authoritative policy bundle. The browser
  may choose among those capabilities, enter the recipient email and bounded
  expiry, and confirm the read-only scope; it never constructs policy bytes,
  CIDs, delegations, or authority material. The host rechecks the policy
  binding for every signing, upload, and public-binding request.
- `SenderScope` is supplied by the host TinyCloud application after the
  selected KV path or named SQL statement is authorized. It includes the
  sender signer, delegation CID, authority-material handle/digest, trusted
  node origin/audience, and exact space. The signing key remains behind the
  authenticated host capability endpoint.
- `uploadEnvelope` is the authenticated create-only registry uploader. The UI
  never returns a secret or chooses a substitute email service.
- `EmailClaimRuntime.verify` binds the locally verified envelope/policy to the
  frozen authority bundle, and `ShareTransport` calls the versioned Node and
  OpenCredentials routes. Sender requests use the persistent Share host's
  same-origin routes, which are trust-bound proxies to those services. The
  transport is `credentials: omit`, redirect rejecting, `no-store`, and
  `no-referrer`.

If the host cannot provide an authenticated capability with its authoritative
policy, the sender page renders an unavailable state rather than inventing a
policy or pretending that a request was delivered. Link creation uploads the
encrypted envelope and publishes its derived public binding; the exact Node
authorization is then verified before OpenCredentials receives the delivery
request. The sender reports requested only after OpenCredentials accepts that
request; it does not claim that the email was read or arrived. The recipient
link is inert on GET and can only enter claim after an explicit **Open
document** activation.
