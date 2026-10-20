/**
 * Build-time only (Node): the user-content deployment, `dist-usercontent/`.
 *
 * It contains ONLY the sandbox documents, the library files with their
 * manifest and NOTICE, and `_headers`. No viewer code, no config, no API: the
 * host holds no credentials and sets no cookies. A second Cloudflare Pages
 * project serves this directory; see docs/user-content-origin.md.
 */
import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";

import { buildArtifactSandboxHtml, ARTIFACT_SANDBOX_PATH } from "../../viewer/artifact-frame.js";
import { buildJsxSandboxHtml, JSX_SANDBOX_PATH } from "../../viewer/jsx-frame.js";
import { buildMermaidSandboxHtml, MERMAID_SANDBOX_PATH } from "../../viewer/mermaid-frame.js";
import { buildJsxRuntime, renderNotice } from "../jsx-runtime/build.js";
import { readJsxFrameCss } from "../jsx-runtime/frame-css.js";
import { USER_CONTENT_MANIFEST_PATH, renderUserContentHeaders } from "./headers.js";

export const MANIFEST_FILE = USER_CONTENT_MANIFEST_PATH.slice(1);

export interface UserContentBuild {
  /** Every file written, relative to `outDir`, sorted. */
  readonly files: readonly string[];
}

export async function buildUserContent(options: { readonly outDir: string; readonly viewerOrigin: string }): Promise<UserContentBuild> {
  const require = createRequire(import.meta.url);
  const runtime = await buildJsxRuntime();
  const outputs = new Map<string, string>([
    [JSX_SANDBOX_PATH.slice(1), buildJsxSandboxHtml(readJsxFrameCss())],
    [ARTIFACT_SANDBOX_PATH.slice(1), buildArtifactSandboxHtml()],
    [MERMAID_SANDBOX_PATH.slice(1), buildMermaidSandboxHtml(readFileSync(require.resolve("mermaid/dist/mermaid.min.js"), "utf8"))],
    [MANIFEST_FILE, `${JSON.stringify(runtime.manifest, null, 2)}\n`],
    ["NOTICE.txt", renderNotice(runtime.packages)],
    ["_headers", renderUserContentHeaders(options.viewerOrigin)],
  ]);
  for (const file of runtime.files) outputs.set(file.fileName, file.text);

  rmSync(options.outDir, { recursive: true, force: true });
  for (const [name, text] of outputs) {
    const target = join(options.outDir, name);
    mkdirSync(dirname(target), { recursive: true });
    writeFileSync(target, text);
  }
  return { files: [...outputs.keys()].sort() };
}
