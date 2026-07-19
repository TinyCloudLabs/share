# Exact-email UI integration boundary

The `/share.html` sender surface and `/s/<cid>` recipient surface contain the
production client state machine. They do not ship a simulated sender identity,
registry uploader, mail provider, credential issuer, or policy authority.

The remaining cross-repository seam is intentionally typed:

- `SenderScope` is supplied by the host TinyCloud application after the
  selected KV path or named SQL statement is authorized. It includes the
  sender signer, delegation CID, authority-material handle/digest, trusted
  node origin/audience, and exact space.
- `uploadEnvelope` is the authenticated create-only registry uploader. The UI
  never returns a secret or chooses a substitute email service.
- `EmailClaimRuntime.verify` binds the locally verified envelope/policy to the
  frozen authority bundle, and `ShareTransport` calls the versioned Node and
  OpenCredentials routes. The transport is `credentials: omit`, redirect
  rejecting, `no-store`, and `no-referrer`.

Until those exact adapters are composed by the cross-repo E1 harness, the
static sender page renders an unavailable state rather than pretending that a
request was delivered. The recipient link is inert on GET and can only enter
claim after an explicit **Open document** activation.
