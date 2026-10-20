/**
 * Permissions-Policy sent with every sandbox document that runs sender code (the
 * artifact and JSX bridges; the policy is inherited by their srcdoc children).
 * The artifact cannot go fullscreen or open Picture-in-Picture over the viewer's
 * chrome, and gets no powerful feature. The frames' `allow=""` already withholds
 * these from the embedder side; this is the same denial from the document side.
 */
export const SANDBOX_PERMISSIONS_POLICY = [
  "fullscreen=()", "picture-in-picture=()", "camera=()", "microphone=()", "geolocation=()", "payment=()",
  "usb=()", "display-capture=()", "screen-wake-lock=()", "web-share=()", "publickey-credentials-get=()",
].join(", ");
