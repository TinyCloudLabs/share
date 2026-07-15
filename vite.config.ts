import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";

import {
  defineConfig,
  loadEnv,
  type Plugin,
  type PreviewServer,
  type ViteDevServer,
} from "vite";

import {
  parseAllowedNodeOrigins,
  parseOpenKeyOrigin,
  parseRegistryOrigin,
  replaceViewerDeploymentCspSources,
} from "./src/viewer/deployment-config.ts";

import {
  MERMAID_SANDBOX_HTTP_HEADERS,
  MERMAID_SANDBOX_PATH,
  buildMermaidSandboxHtml,
} from "./src/viewer/mermaid-frame.ts";

/**
 * Serve viewer.html on /s/<cid> routes (dev + preview). The spec site stays
 * at / (index.html) — untouched. In production the static host needs the
 * same rewrite rule: /s/* → /viewer.html.
 */
function shareRouteRewrite(): Plugin {
  const rewrite = (url: string | undefined): string | undefined => {
    const path = (url ?? "").split("?")[0] ?? "";
    // Fragment (#k=…) never reaches the server, so matching the path only
    // is exact. CID charset per the link codec: lowercase base32.
    return /^\/s\/[a-z2-7]+$/.test(path) ? "/viewer.html" : undefined;
  };
  return {
    name: "share-route-rewrite",
    configureServer(server) {
      server.middlewares.use((req, _res, next) => {
        const target = rewrite(req.url);
        if (target !== undefined) req.url = target;
        next();
      });
    },
    configurePreviewServer(server) {
      server.middlewares.use((req, _res, next) => {
        const target = rewrite(req.url);
        if (target !== undefined) req.url = target;
        next();
      });
    },
  };
}

/**
 * Serve (dev/preview) and emit (build) the mermaid sandbox document at
 * MERMAID_SANDBOX_PATH: the shared HTML builder (src/viewer/mermaid-frame.ts)
 * with the version-pinned, self-hosted mermaid IIFE bundle INLINED — the
 * frame's CSP allows only inline scripts (no network at all), per viewer
 * spec §3.2. Static hosts serve the emitted asset as-is.
 */
function mermaidSandboxHtml(): Plugin {
  let html: string | undefined;
  const getHtml = (): string => {
    if (html === undefined) {
      const require = createRequire(import.meta.url);
      html = buildMermaidSandboxHtml(
        readFileSync(require.resolve("mermaid/dist/mermaid.min.js"), "utf8"),
      );
    }
    return html;
  };
  const serve = (server: ViteDevServer | PreviewServer): void => {
    server.middlewares.use((req, res, next) => {
      const path = (req.url ?? "").split("?")[0] ?? "";
      if (path !== MERMAID_SANDBOX_PATH) {
        next();
        return;
      }
      res.setHeader("content-type", "text/html; charset=utf-8");
      res.setHeader("x-content-type-options", "nosniff");
      // Refuse third-party embedding: frame-ancestors MUST arrive as an
      // HTTP header (a <meta> CSP cannot carry it). PRODUCTION static hosts
      // must send these same headers for this path — the build ships a
      // public/_headers rule for Cloudflare Pages; any other host needs the
      // equivalent configuration.
      for (const [name, value] of MERMAID_SANDBOX_HTTP_HEADERS) {
        res.setHeader(name, value);
      }
      res.end(getHtml());
    });
  };
  return {
    name: "mermaid-sandbox-html",
    configureServer: serve,
    configurePreviewServer: serve,
    generateBundle() {
      this.emitFile({
        type: "asset",
        fileName: MERMAID_SANDBOX_PATH.slice(1),
        source: getHtml(),
      });
    },
  };
}

function viewerDeploymentCsp(
  nodeOrigins: readonly string[],
  openKeyOrigin: string,
  registryOrigin: string,
): Plugin {
  const replaceSources = (text: string): string =>
    replaceViewerDeploymentCspSources(text, {
      registryOrigin,
      nodeOrigins,
      openKeyOrigin,
    });
  return {
    name: "viewer-deployment-csp",
    transformIndexHtml: {
      order: "pre",
      handler(html, context) {
        if (!context.filename.endsWith("viewer.html")) return html;
        return replaceSources(html);
      },
    },
    writeBundle(outputOptions) {
      const outputDirectory = outputOptions.dir ?? "dist";
      const headersPath = fileURLToPath(new URL(`${outputDirectory}/_headers`, `file://${process.cwd()}/`));
      if (existsSync(headersPath)) {
        writeFileSync(headersPath, replaceSources(readFileSync(headersPath, "utf8")));
      }
    },
  };
}

export default defineConfig(({ command, mode }) => {
  const env = loadEnv(mode, process.cwd(), "");
  const nodeOrigins = parseAllowedNodeOrigins(env.VITE_SHARE_ALLOWED_NODE_ORIGINS);
  const openKeyOrigin = parseOpenKeyOrigin(env.VITE_SHARE_OPENKEY_ORIGIN);
  const registryOrigin = parseRegistryOrigin(
    env.VITE_SHARE_REGISTRY_URL,
    command === "build",
  );
  return {
    base: "/",
    plugins: [
      shareRouteRewrite(),
      mermaidSandboxHtml(),
      viewerDeploymentCsp(nodeOrigins, openKeyOrigin, registryOrigin),
    ],
    build: {
      rollupOptions: {
        input: {
          main: fileURLToPath(new URL("index.html", import.meta.url)),
          viewer: fileURLToPath(new URL("viewer.html", import.meta.url)),
        },
      },
    },
  };
});
