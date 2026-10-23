/**
 * Browser harness for the full-page viewer: renders a markdown or single-file
 * HTML fixture through presentShare (the glue main.ts uses after a bearer
 * receive), or one of the honest state screens. `probe` is the origin of a
 * loopback server that must never receive a request.
 */
import "../../../src/email-share/recipient.css";
import "../../../src/viewer/viewer.css";
import { presentShare } from "../../../src/viewer/present.js";
import { presentationEnvelope } from "../../../src/viewer/resolve.js";
import { renderLinkNeeded, renderShareUnavailable } from "../../../src/viewer/ui.js";
import { SaveCopyError, type SaveFailureReason, type SaveToTinyCloud } from "../../../src/viewer/save-copy.js";
import report from "./report.md?raw";
import page from "./page.html?raw";
import gaps from "./gaps.html?raw";
import app from "./app.jsx?raw";
import links from "./links.md?raw";

const params = new URLSearchParams(location.search);
const kind = params.get("kind") ?? "md";
// The loopback page a links-fixture click opens: a real popup target the e2e can inspect.
const landing = params.get("landing") ?? "http://127.0.0.1:9/landing";
const probe = params.get("probe") ?? "http://127.0.0.1:9";
// Plant a recognisable fake link secret the way main.ts receives a real one: it
// arrives in the fragment, is scrubbed at once, and then lives only in the
// Copy link closure. The e2e asserts it appears nowhere else.
history.replaceState(null, "", `${location.pathname}${location.search}#tc1=harness-secret`);
history.replaceState(null, "", `${location.pathname}${location.search}`);
const root = document.getElementById("viewer")!;
document.documentElement.classList.remove("viewer-first-paint");

/**
 * `?save=control` offers Save a copy with a save the e2e settles by hand
 * (`window.__saveControl`), so every state of the bar can be looked at. The
 * real sign-in is exercised by the joined gate, not here.
 */
const saveToTinyCloud: SaveToTinyCloud = (copy, progress) => new Promise((resolve, reject) => {
  Object.assign(window, {
    __saveControl: {
      copy,
      approval: progress.approval,
      resolve: (name = "q3-agent-report.md") => resolve({ path: `files-for-you/v1/${encodeURIComponent(name)}`, name }),
      reject: (reason: SaveFailureReason) => reject(new SaveCopyError(reason)),
    },
  });
});
try {
  const state = params.get("state");
  if (state === "needs-link") {
    renderLinkNeeded(root);
  } else if (state === "revoked" || state === "expired" || state === "unavailable") {
    renderShareUnavailable(root, state, state === "expired" ? "2026-10-12T00:00:00.000Z" : undefined, () => undefined);
  } else {
    const filename = kind === "md" ? "q3-agent-report.md" : kind === "links" ? "q3-links.md" : kind === "gaps" ? "gaps.html" : kind === "jsx" ? "counter.jsx" : "q3-agent-report.html";
    const source = (kind === "md" ? report : kind === "links" ? links.replaceAll("__LANDING__", landing) : kind === "gaps" ? gaps : kind === "jsx" ? app : page).replaceAll("__PROBE__", probe);
    const path = `xyz.tinycloud.share/shares/viewer-page/${filename}`;
    await presentShare(root, {
      state: "ok",
      access: params.get("access") === "policy" ? "policy" : "bearer",
      senderVerified: false,
      contentBytes: new TextEncoder().encode(source),
      envelope: presentationEnvelope({
        protocol: "tinycloud-share",
        version: 1,
        shareId: `${path}-${params.get("nonce") ?? "a"}`,
        origin: location.origin,
        target: { kind: "bearer", origin: "https://node.tinycloud.xyz", nodeAudience: "", spaceId: "space" },
        resource: { kind: "exact", path },
        actions: ["tinycloud.kv/get"],
        display: { filename },
        expiresAt: "2030-01-01T00:00:00.000Z",
      } as Parameters<typeof presentationEnvelope>[0]),
    }, { shareUrl: `${location.origin}/viewer#tc1=harness-secret`, ...(params.get("save") === null ? {} : { saveToTinyCloud }) });
  }
  document.documentElement.dataset.ready = "yes";
} catch (error) {
  console.error("viewer page harness failed", error);
  document.documentElement.dataset.ready = "error";
}
