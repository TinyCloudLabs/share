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
import { renderShareUnavailable } from "../../../src/viewer/ui.js";
import report from "./report.md?raw";
import page from "./page.html?raw";
import gaps from "./gaps.html?raw";

const params = new URLSearchParams(location.search);
const kind = params.get("kind") ?? "md";
const probe = params.get("probe") ?? "http://127.0.0.1:9";
const root = document.getElementById("viewer")!;
document.documentElement.classList.remove("viewer-first-paint");

try {
  const state = params.get("state");
  if (state === "revoked" || state === "expired" || state === "unavailable") {
    renderShareUnavailable(root, state, state === "expired" ? "2026-10-12T00:00:00.000Z" : undefined);
  } else {
    const filename = kind === "md" ? "q3-agent-report.md" : kind === "gaps" ? "gaps.html" : "q3-agent-report.html";
    const source = (kind === "md" ? report : kind === "gaps" ? gaps : page).replaceAll("__PROBE__", probe);
    const path = `xyz.tinycloud.share/shares/viewer-page/${filename}`;
    await presentShare(root, {
      state: "ok",
      access: "bearer",
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
    }, { shareUrl: `${location.origin}/viewer#tc1=harness-secret` });
  }
  document.documentElement.dataset.ready = "yes";
} catch (error) {
  console.error("viewer page harness failed", error);
  document.documentElement.dataset.ready = "error";
}
