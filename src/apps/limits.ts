/**
 * What the page says, in plain words, about what the sandbox does not stop. One place, so the runner, the install
 * sheet, the apps page and the docs say the same thing.
 *
 * The sandbox's CSP stops every content and script request but does NOT govern a prerender, a preconnect, a DNS prefetch,
 * `<a ping>` or WebRTC; those are why the frame's runtime refuses the elements and attributes that start them
 * (src/artifact/jsx-runtime/url-guard.ts). That guard is best effort: these paths are known closed (measured by
 * test/e2e-jsx.mjs and the runner gate), same-realm code may find others. What is certain: a page trying to open another
 * page makes the browser look the address up and open one connection (no request is sent), and the address can carry a
 * little data. So the page never says "no network access".
 */
export const CAUTION = "Some browser requests can't be blocked. Install apps you trust. Beta: use sample data only.";

/** The one-line list of what still leaks, measured by test/e2e-prod/runner-gate.mjs (docs/tiny-app-runner.md, "Known limits"). */
export const KNOWN_LIMITS = "Known limits: an app can still reveal that you opened it (your IP address and the time). Some other browser requests can still carry what the app reads to an address it picks, and trying to open another page makes your browser look up and connect to an address it picks.";
