/**
 * Browser harness for Markdown shares with Mermaid diagrams (TC-546). Renders
 * the `?fixture=` document through presentShare — the same glue main.ts uses
 * after a bearer receive — so the e2e exercises the shipped content path: the
 * opaque-origin Mermaid sandbox, SVG re-sanitization, and the scriptless
 * preview frame.
 */
import "../../../src/email-share/recipient.css";
import "../../../src/viewer/viewer.css";
import { presentShare } from "../../../src/viewer/present.js";
import { presentationEnvelope } from "../../../src/viewer/resolve.js";
import flowchart from "./flowchart.md?raw";
import flowchartFrontmatter from "./flowchart-frontmatter.md?raw";
import flowchartInit from "./flowchart-init.md?raw";
import sequence from "./sequence.md?raw";

const FIXTURES: Readonly<Record<string, string>> = {
  flowchart,
  "flowchart-init": flowchartInit,
  "flowchart-frontmatter": flowchartFrontmatter,
  sequence,
};
const name = new URLSearchParams(location.search).get("fixture") ?? "flowchart";
const filename = `${name}.md`;
const path = `applications/share/${filename}`;
const root = document.getElementById("viewer")!;
try {
  const fixture = FIXTURES[name];
  if (fixture === undefined) throw new Error(`unknown fixture ${name}`);
  await presentShare(root, {
    state: "ok",
    access: "bearer",
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
    } as Parameters<typeof presentationEnvelope>[0]),
  }, { shareUrl: location.href });
  document.documentElement.dataset.ready = "yes";
} catch (error) {
  console.error("Markdown share harness failed", error);
  document.documentElement.dataset.ready = "error";
}
