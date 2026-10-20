/**
 * What the page says, in plain words, about what the sandbox does not stop. One place, so the runner, the install
 * sheet, the apps page and the docs say the same thing.
 *
 * The sandbox stops every content and script request (the frame's CSP), and the frame's runtime refuses the
 * elements that make the browser ask for a URL on its own (src/artifact/jsx-runtime/url-guard.ts). That second
 * part is best effort: a page's code runs in the same realm. Measured (test/e2e-jsx.mjs, the runner gate): prerender,
 * prefetch, preconnect, dns-prefetch, <a ping>, <img>, <form>, <meta refresh>, WebRTC and the rest reach nothing.
 * What is left is a page trying to open another page: the browser still looks the address up and opens one connection
 * (no request is sent), and the address can carry a little data. So the page never says "no network access".
 */
export const CAUTION = "Some browser requests can't be blocked. Install apps you trust. Beta: use sample data only.";

/** The one-line list of what still leaks, measured by test/e2e-prod/runner-gate.mjs (docs/tiny-app-runner.md, "Known limits"). */
export const KNOWN_LIMITS = "Known limits: an app can still reveal that you opened it (your IP address and the time), and by trying to open another page it can make your browser look up or connect to an address it picks, which can carry a little data.";
