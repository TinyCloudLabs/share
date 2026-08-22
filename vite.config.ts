import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";

import { defineConfig, type Plugin, type PreviewServer, type ViteDevServer } from "vite";

import {
  MERMAID_SANDBOX_HTTP_HEADERS,
  MERMAID_SANDBOX_PATH,
  buildMermaidSandboxHtml,
} from "./src/viewer/mermaid-frame.ts";
import {
  ARTIFACT_SANDBOX_HTTP_HEADERS,
  ARTIFACT_SANDBOX_PATH,
  buildArtifactSandboxHtml,
} from "./src/viewer/artifact-frame.ts";

/** Share is a static UX. Every live authority/data operation goes to TinyCloud. */
function shareRouteRewrite(): Plugin {
  const rewrite = (url: string | undefined): string | undefined => {
    const path = (url ?? "").split("?", 1)[0] ?? "";
    if (path === "/share") return "/share.html";
    if (path === "/viewer") return "/viewer.html";
    if (path === "/how-it-works" || path === "/how-it-works/") return "/how-it-works.html";
    return undefined;
  };
  const serve = (server: ViteDevServer | PreviewServer): void => {
    server.middlewares.use((request, _response, next) => {
      const target = rewrite(request.url);
      if (target !== undefined) request.url = target;
      next();
    });
  };
  return { name: "share-route-rewrite", configureServer: serve, configurePreviewServer: serve };
}

function staticSecurityHeaders(): Plugin {
  const serve = (server: ViteDevServer | PreviewServer): void => {
    server.middlewares.use((_request, response, next) => {
      response.setHeader("cache-control", "no-store, no-transform");
      response.setHeader("referrer-policy", "no-referrer");
      response.setHeader("x-content-type-options", "nosniff");
      next();
    });
  };
  return { name: "share-static-security-headers", configureServer: serve, configurePreviewServer: serve };
}

function mermaidSandboxHtml(): Plugin {
  let html: string | undefined;
  const getHtml = (): string => {
    if (html === undefined) {
      const require = createRequire(import.meta.url);
      html = buildMermaidSandboxHtml(readFileSync(require.resolve("mermaid/dist/mermaid.min.js"), "utf8"));
    }
    return html;
  };
  const serve = (server: ViteDevServer | PreviewServer): void => {
    server.middlewares.use((request, response, next) => {
      if ((request.url ?? "").split("?", 1)[0] !== MERMAID_SANDBOX_PATH) { next(); return; }
      response.setHeader("content-type", "text/html; charset=utf-8");
      for (const [name, value] of MERMAID_SANDBOX_HTTP_HEADERS) response.setHeader(name, value);
      response.end(getHtml());
    });
  };
  return {
    name: "mermaid-sandbox-html",
    configureServer: serve,
    configurePreviewServer: serve,
    generateBundle() { this.emitFile({ type: "asset", fileName: MERMAID_SANDBOX_PATH.slice(1), source: getHtml() }); },
  };
}

function artifactSandboxHtml(): Plugin {
  const html = buildArtifactSandboxHtml();
  const serve = (server: ViteDevServer | PreviewServer): void => {
    server.middlewares.use((request, response, next) => {
      if ((request.url ?? "").split("?", 1)[0] !== ARTIFACT_SANDBOX_PATH) { next(); return; }
      response.setHeader("content-type", "text/html; charset=utf-8");
      for (const [name, value] of ARTIFACT_SANDBOX_HTTP_HEADERS) response.setHeader(name, value);
      response.end(html);
    });
  };
  return {
    name: "artifact-sandbox-html",
    configureServer: serve,
    configurePreviewServer: serve,
    generateBundle() { this.emitFile({ type: "asset", fileName: ARTIFACT_SANDBOX_PATH.slice(1), source: html }); },
  };
}

export default defineConfig({
  base: "/",
  plugins: [shareRouteRewrite(), staticSecurityHeaders(), mermaidSandboxHtml(), artifactSandboxHtml()],
  build: {
    rollupOptions: {
      input: {
        main: fileURLToPath(new URL("index.html", import.meta.url)),
        howItWorks: fileURLToPath(new URL("how-it-works.html", import.meta.url)),
        share: fileURLToPath(new URL("share.html", import.meta.url)),
        viewer: fileURLToPath(new URL("viewer.html", import.meta.url)),
      },
    },
  },
});
