import { readFileSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { defineConfig, loadEnv, type Plugin, type PreviewServer, type ResolvedConfig, type ViteDevServer } from "vite";

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
import {
  JSX_SANDBOX_HTTP_HEADERS,
  JSX_SANDBOX_PATH,
  buildJsxSandboxHtml,
} from "./src/viewer/jsx-frame.ts";
import { buildJsxRuntime, renderNotice, type JsxRuntimeBuild } from "./src/artifact/jsx-runtime/build.ts";
import { readJsxFrameCss } from "./src/artifact/jsx-runtime/frame-css.ts";
import { renderViewerHeaders, withUserContentOrigin } from "./src/artifact/user-content/headers.ts";
import { parseUserContentOrigin } from "./src/viewer/user-content-origin.ts";
import { renderLandingTemplate } from "./src/landing/brand.ts";

/** Share is a static UX. Every live authority/data operation goes to TinyCloud. */
function shareRouteRewrite(): Plugin {
  const rewrite = (url: string | undefined): string | undefined => {
    const path = (url ?? "").split("?", 1)[0] ?? "";
    if (path === "/share") return "/share/index.html";
    if (path === "/viewer") return "/viewer/index.html";
    if (path.startsWith("/s/")) return "/viewer/index.html";
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

function mermaidSandboxHtml(userContentOrigin: string): Plugin {
  let html: string | undefined;
  const getHtml = (): string => {
    if (html === undefined) {
      const require = createRequire(import.meta.url);
      html = buildMermaidSandboxHtml(readFileSync(require.resolve("mermaid/dist/mermaid.min.js"), "utf8"));
    }
    return html;
  };
  // Production serves the document on both paths (Cloudflare redirects the
  // .html form to the extensionless one) under one _headers contract; dev
  // and preview answer both with the same document and frame headers.
  const routes = new Set([MERMAID_SANDBOX_PATH, MERMAID_SANDBOX_PATH.replace(/\.html$/, "")]);
  const serve = (server: ViteDevServer | PreviewServer): void => {
    server.middlewares.use((request, response, next) => {
      if (!routes.has((request.url ?? "").split("?", 1)[0] ?? "")) { next(); return; }
      response.setHeader("content-type", "text/html; charset=utf-8");
      for (const [name, value] of MERMAID_SANDBOX_HTTP_HEADERS) response.setHeader(name, value);
      response.end(getHtml());
    });
  };
  return {
    name: "mermaid-sandbox-html",
    configureServer: serve,
    configurePreviewServer: serve,
    generateBundle() { if (userContentOrigin === "") this.emitFile({ type: "asset", fileName: MERMAID_SANDBOX_PATH.slice(1), source: getHtml() }); },
  };
}

function artifactSandboxHtml(userContentOrigin: string): Plugin {
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
    generateBundle() { if (userContentOrigin === "") this.emitFile({ type: "asset", fileName: ARTIFACT_SANDBOX_PATH.slice(1), source: html }); },
  };
}

/**
 * The JSX renderer's two build products: the sandbox bridge document, and the
 * per-library module files with their sha256 manifest (served as the virtual
 * module `virtual:tc-jsx-manifest`, which only the lazy JSX chunk imports).
 * Dev/preview answer the same paths from the same in-memory build.
 */
function jsxSandbox(userContentOrigin: string): Plugin {
  const manifestId = "virtual:tc-jsx-manifest";
  const html = buildJsxSandboxHtml(readJsxFrameCss());
  let runtime: Promise<JsxRuntimeBuild> | undefined;
  const getRuntime = (): Promise<JsxRuntimeBuild> => (runtime ??= buildJsxRuntime());
  const pages = new Set([JSX_SANDBOX_PATH, JSX_SANDBOX_PATH.replace(/\.html$/, "")]);
  const serve = (server: ViteDevServer | PreviewServer): void => {
    server.middlewares.use((request, response, next) => {
      const path = (request.url ?? "").split("?", 1)[0] ?? "";
      if (pages.has(path)) {
        response.setHeader("content-type", "text/html; charset=utf-8");
        for (const [name, value] of JSX_SANDBOX_HTTP_HEADERS) response.setHeader(name, value);
        response.end(html);
        return;
      }
      if (path.startsWith("/assets/jsx-runtime/")) {
        getRuntime().then(({ files }) => {
          const file = files.find((candidate) => candidate.url === path);
          if (file === undefined) { next(); return; }
          response.setHeader("content-type", "text/javascript; charset=utf-8");
          response.end(file.text);
        }, next);
        return;
      }
      next();
    });
  };
  return {
    name: "jsx-sandbox",
    configureServer: serve,
    configurePreviewServer: serve,
    resolveId: (id) => (id === manifestId ? `\0${manifestId}` : undefined),
    async load(id) {
      if (id !== `\0${manifestId}`) return undefined;
      return `export default ${JSON.stringify((await getRuntime()).manifest)};`;
    },
    async generateBundle() {
      // With a separate user-content origin this build ships none of the sandbox
      // documents or library files (`npm run build:usercontent` does); the manifest
      // the viewer embeds still pins their digests.
      if (userContentOrigin !== "") return;
      this.emitFile({ type: "asset", fileName: JSX_SANDBOX_PATH.slice(1), source: html });
      const built = await getRuntime();
      for (const file of built.files) this.emitFile({ type: "asset", fileName: file.fileName, source: file.text });
      this.emitFile({ type: "asset", fileName: "NOTICE.txt", source: renderNotice(built.packages) });
    },
  };
}

/**
 * With a user-content origin, the viewer's `_headers` loses the sandbox routes and
 * its policies (header and the viewer page's meta tag) name exactly that origin in
 * `frame-src` and `connect-src`. Empty origin: nothing changes.
 */
function userContentOriginPolicy(userContentOrigin: string): Plugin {
  let config: ResolvedConfig;
  return {
    name: "user-content-origin-policy",
    configResolved(resolved) { config = resolved; },
    transformIndexHtml: {
      order: "pre",
      handler: (html, ctx) => ctx.filename.endsWith("/viewer/index.html")
        ? html.replace(/(<meta http-equiv="Content-Security-Policy" content=")([^"]*)(")/, (_match, open: string, csp: string, close: string) => `${open}${withUserContentOrigin(csp, userContentOrigin)}${close}`)
        : html,
    },
    // The policy above names the origin; the viewer's code (src/viewer/user-content-origin.ts)
    // must carry the same one. If the build did not bake it into a chunk the viewer would
    // frame same-origin while its CSP allows the user-content host, so fail the build instead.
    generateBundle(_options, bundle) {
      if (userContentOrigin === "") return;
      const baked = Object.values(bundle).some((item) => item.type === "chunk" && item.code.includes(`"${userContentOrigin}"`));
      if (!baked) this.error(`VITE_USER_CONTENT_ORIGIN ${userContentOrigin} is in the CSP but no JS chunk carries it`);
    },
    closeBundle() {
      if (userContentOrigin === "" || config.command !== "build") return;
      const target = resolve(config.root, config.build.outDir, "_headers");
      writeFileSync(target, renderViewerHeaders(readFileSync(target, "utf8"), userContentOrigin));
    },
  };
}

/**
 * Fills the {{TOKEN}} placeholders in the landing HTML from src/landing/brand.ts.
 * Scoped to the root index.html: other pages are never templated, so a stray
 * `{{UPPER}}` in them cannot fail the build.
 */
function landingTemplate(): Plugin {
  const landing = fileURLToPath(new URL("index.html", import.meta.url));
  return {
    name: "landing-template",
    transformIndexHtml: {
      order: "pre",
      handler: (html, ctx) => (ctx.filename === landing ? renderLandingTemplate(html) : html),
    },
  };
}

export default defineConfig(({ mode }) => {
  // Where sandbox documents and runtime files are served from; "" = same origin.
  const userContentOrigin = parseUserContentOrigin(loadEnv(mode, process.cwd(), "VITE_")["VITE_USER_CONTENT_ORIGIN"]);
  return {
    base: "/",
    plugins: [landingTemplate(), shareRouteRewrite(), staticSecurityHeaders(), mermaidSandboxHtml(userContentOrigin), artifactSandboxHtml(userContentOrigin), jsxSandbox(userContentOrigin), userContentOriginPolicy(userContentOrigin)],
    build: {
      rollupOptions: {
        input: {
          main: fileURLToPath(new URL("index.html", import.meta.url)),
          howItWorks: fileURLToPath(new URL("how-it-works.html", import.meta.url)),
          share: fileURLToPath(new URL("share/index.html", import.meta.url)),
          viewer: fileURLToPath(new URL("viewer/index.html", import.meta.url)),
        },
      },
    },
  };
});
