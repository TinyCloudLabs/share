/**
 * Browser harness for single-file HTML shares. It plants viewer-origin
 * secrets (storage, cookie, URL fragment), then renders the fixture through
 * presentShare — the same glue main.ts uses after a bearer receive or an
 * addressed resolve — so the e2e exercises the shipped content path.
 */
import "../../../src/email-share/recipient.css";
import "../../../src/viewer/viewer.css";
import { presentShare } from "../../../src/viewer/present.js";
import { presentationEnvelope } from "../../../src/viewer/resolve.js";
import report from "./report.html?raw";
import hostile from "./hostile.html?raw";
import navigateEarly from "./navigate-early.html?raw";
import navigateLate from "./navigate-late.html?raw";
import headAttributes from "./head-attributes.html?raw";
import leadingComments from "./leading-comments.html?raw";

const FIXTURES: Readonly<Record<string, string>> = {
  report,
  hostile,
  "navigate-early": navigateEarly,
  "navigate-late": navigateLate,
  "head-attributes": headAttributes,
  "leading-comments": leadingComments,
};
const params = new URLSearchParams(location.search);
const name = params.get("fixture") ?? "report";
const fixture = (FIXTURES[name] ?? report)
  .replaceAll("__VIEWER_ORIGIN__", location.origin)
  .replaceAll("__STUN_PORT__", params.get("stun") ?? "3478");
const filename = `${name}.html`;
const addressed = params.get("access") === "addressed";

sessionStorage.setItem("tc-viewer-secret", "session-secret-8c1");
localStorage.setItem("tc-viewer-secret", "local-secret-8c1");
document.cookie = "tc_viewer_secret=cookie-secret-8c1; path=/; SameSite=Lax";
history.replaceState(null, "", `${location.pathname}${location.search}#tc1=fragment-secret-8c1`);

const root = document.getElementById("viewer")!;
const path = `applications/share/${filename}`;
// Main-thread stalls during presentation (Long Tasks API, >50 ms entries),
// published on the root element for the e2e to read.
const longTasks: number[] = [];
const presentStarted = performance.now();
document.documentElement.dataset.longTasks = "";
new PerformanceObserver((list) => {
  for (const entry of list.getEntries()) if (entry.startTime >= presentStarted) longTasks.push(Math.round(entry.duration));
  document.documentElement.dataset.longTasks = longTasks.join(",");
}).observe({ type: "longtask", buffered: true });
try {
  await presentShare(root, {
    state: "ok",
    access: addressed ? "policy" : "bearer",
    senderVerified: false,
    contentBytes: new TextEncoder().encode(fixture),
    envelope: presentationEnvelope({
      protocol: "tinycloud-share",
      version: 1,
      shareId: path,
      origin: location.origin,
      target: { kind: "bearer", origin: "https://node.tinycloud.xyz", nodeAudience: "", spaceId: "space" },
      resource: { kind: "exact", path },
      actions: ["tinycloud.kv/get"],
      display: { filename },
      expiresAt: "2030-01-01T00:00:00.000Z",
    // Bearer links carry no signed media type; addressed links sign text/html.
    } as Parameters<typeof presentationEnvelope>[0], addressed ? { filename, mediaType: "text/html" } : undefined),
  }, { shareUrl: location.href });
  document.documentElement.dataset.ready = "yes";
} catch (error) {
  console.error("HTML share harness failed", error);
  document.documentElement.dataset.ready = "error";
}
