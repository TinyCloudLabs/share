/**
 * Viewer entry (viewer.html), active on /s/<cid>#k=… routes.
 *
 * Key hygiene: the fragment key is captured into a local string ONCE, then
 * immediately scrubbed out of location.hash and the current history entry
 * (scrubKeyFragment) BEFORE anything is fetched or rendered — so a later
 * same-origin XSS cannot read the key back out of the URL bar or history.
 * resolveShare consumes the parsed key in memory and zeroes it on every
 * return path. Nothing here logs, stores, or transmits the fragment.
 */
import "./viewer.css";

import { REGISTRY_BASE_URL } from "./config.js";
import { resolveShare } from "./resolve.js";
import { renderResolving, renderViewerState } from "./ui.js";
import { hrefForParse, scrubKeyFragment } from "./url.js";

async function boot(): Promise<void> {
  const root = document.getElementById("viewer");
  if (root === null) throw new Error("viewer root element missing");
  // Capture the href (the only read of the fragment), then scrub the key
  // from the address bar + history BEFORE any network or render work. The
  // loopback http→https rewrite inside hrefForParse is dev-build-only.
  const href = hrefForParse(window.location, import.meta.env.DEV);
  scrubKeyFragment(window.location, window.history);
  renderResolving(root);
  const result = await resolveShare(href, {
    registryBaseUrl: REGISTRY_BASE_URL,
  });
  renderViewerState(root, result);
}

void boot();
