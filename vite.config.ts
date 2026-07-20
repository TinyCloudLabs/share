import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";

import {
  defineConfig,
  type Plugin,
  type PreviewServer,
  type ViteDevServer,
} from "vite";

import {
  MERMAID_SANDBOX_HTTP_HEADERS,
  MERMAID_SANDBOX_PATH,
  buildMermaidSandboxHtml,
} from "./src/viewer/mermaid-frame.ts";
import { createShareHostFromEnv } from "./src/host/share-adapter.ts";
import { loadTrustBundle } from "./src/host/trust-bundle.ts";

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
    transformIndexHtml(html, context) {
      if (process.env.SHARE_TRUST_BUNDLE_ALLOW_TEST !== "true" || (context.path !== "/share.html" && context.path !== "/viewer.html")) return html;
      return html.replaceAll("https://node.tinycloud.xyz", loadTrustBundle().public.nodeOrigin);
    },
    generateBundle() {
      this.emitFile({
        type: "asset",
        fileName: MERMAID_SANDBOX_PATH.slice(1),
        source: getHtml(),
      });
    },
  };
}

function shareHostAdapter(): Plugin {
  let adapter: ReturnType<typeof createShareHostFromEnv> | undefined;
  const route = (path: string): boolean => path === "/.well-known/tinycloud-share/config.json" || path === "/api/share/capability" || path === "/api/share/sign" || path === "/api/share/bindings" || path.startsWith("/.well-known/tinycloud-share/bindings/") || path === "/registry" || path.startsWith("/registry/");
  const ensure = (): ReturnType<typeof createShareHostFromEnv> | undefined => {
    if (adapter !== undefined) return adapter;
    try { adapter = createShareHostFromEnv(); return adapter; }
    catch (error) {
      if (process.env.SHARE_DEPLOY_STARTUP === "true") throw error;
      return undefined;
    }
  };
  const serve = (server: ViteDevServer | PreviewServer): void => {
    if (process.env.SHARE_DEPLOY_STARTUP === "true") ensure();
    server.middlewares.use((req, res, next) => {
      const path = (req.url ?? "").split("?")[0] ?? "";
      if (!route(path)) { next(); return; }
      const host = ensure();
      if (host === undefined) { res.writeHead(503, JSON_HEADERS); res.end(JSON.stringify({ error: { code: "capability_unavailable" } })); return; }
      const chunks: Buffer[] = [];
      req.on("data", (chunk: Buffer) => chunks.push(chunk));
      req.on("end", () => void (async () => {
        const body = Buffer.concat(chunks);
        const requestInit: RequestInit & { duplex?: "half" } = { method: req.method ?? "GET", headers: Object.fromEntries(Object.entries(req.headers).filter((entry): entry is [string, string] => typeof entry[1] === "string")), ...(body.length === 0 ? {} : { body: new Uint8Array(body), duplex: "half" }) };
        const response = await host.handler(new Request(`http://${req.headers.host ?? "127.0.0.1"}${req.url ?? path}`, requestInit));
        res.writeHead(response.status, Object.fromEntries(response.headers));
        res.end(Buffer.from(await response.arrayBuffer()));
      })().catch(() => { if (!res.headersSent) res.writeHead(500, JSON_HEADERS); res.end(JSON.stringify({ error: { code: "capability_unavailable" } })); }));
    });
  };
  return {
    name: "share-host-adapter",
    configureServer: serve,
    configurePreviewServer: serve,
    generateBundle() {
      if (process.env.SHARE_TRUST_BUNDLE === undefined) {
        if (process.env.SHARE_DEPLOY_BUILD === "true") throw new Error("SHARE_TRUST_BUNDLE is required for deploy builds");
        return;
      }
      const bundle = loadTrustBundle();
      const publicConfig = { version: "tinycloud.share-email-claim/config-v1", shareOrigin: bundle.public.shareOrigin, registryOrigin: bundle.public.registryOrigin, nodeOrigin: bundle.public.nodeOrigin, credentialsOrigin: bundle.public.credentialsOrigin, nodeAudience: bundle.public.nodeAudience, issuerDid: bundle.public.issuerDid, issuerVct: bundle.public.issuerVct, nodeInvitationKid: bundle.public.nodeInvitationKid, nodeInvitationPublicKey: bundle.public.nodeInvitationPublicKey, nodeKeyVersion: bundle.public.nodeKeyVersion, issuerKeyVersion: bundle.public.issuerKeyVersion, issuerPublicKey: bundle.public.issuerPublicKey };
      this.emitFile({ type: "asset", fileName: ".well-known/tinycloud-share/config.json", source: `${JSON.stringify(publicConfig)}\n` });
    },
  };
}

const JSON_HEADERS = { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" };

export default defineConfig({
  base: "/",
  plugins: [shareRouteRewrite(), mermaidSandboxHtml(), shareHostAdapter()],
  build: {
    rollupOptions: {
      input: {
        main: fileURLToPath(new URL("index.html", import.meta.url)),
        share: fileURLToPath(new URL("share.html", import.meta.url)),
        viewer: fileURLToPath(new URL("viewer.html", import.meta.url)),
      },
    },
  },
});
