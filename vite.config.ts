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
import { senderOnlyRoute } from "./src/host/production-server.ts";
import { cloudflareHeaders, loadTrustBundle, securityHeadersForPath } from "./src/host/trust-bundle.ts";
import { sanitizeUpstreamRequest, sanitizeUpstreamResponse, upstreamForPath } from "./src/host/upstream.ts";

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
    if (/^\/s\/[a-z2-7]+$/.test(path)) return "/viewer.html";
    if (path === "/share") return "/share.html";
    if (path === "/viewer") return "/viewer.html";
    if (path === "/how-it-works" || path === "/how-it-works/") return "/how-it-works.html";
    return undefined;
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
  const route = (path: string): boolean => path === "/.well-known/tinycloud-share/config.json" || path === "/api/share/auth/openkey/nonce" || path === "/api/share/auth/openkey" || path === "/api/share/auth/login" || path === "/api/share/auth/logout" || path === "/api/share/capability" || path === "/api/share/capabilities" || path === "/api/share/sign" || path === "/api/share/bindings" || path.startsWith("/.well-known/tinycloud-share/bindings/") || path.startsWith("/api/share/link-only/registry/") || path === "/registry" || path.startsWith("/registry/") || path.startsWith("/share/v1/") || path.startsWith("/v1/share-email/");
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
        const bundle = loadTrustBundle();
        const upstream = upstreamForPath(bundle, path);
        if (upstream !== undefined) {
          if (!host.readiness.senderReady && senderOnlyRoute(path)) {
            res.writeHead(503, JSON_HEADERS);
            res.end(JSON.stringify({ error: { code: "sender_not_ready" } }));
            return;
          }
          const method = req.method ?? "GET";
          const headers = sanitizeUpstreamRequest(path, method, new Headers(Object.fromEntries(Object.entries(req.headers).filter((entry): entry is [string, string] => typeof entry[1] === "string"))), body.length, bundle.public.shareOrigin);
          const target = new URL(`${path}${new URL(req.url ?? path, "http://share.invalid").search}`, upstream.origin);
          const upstreamResponse = await fetch(target, { method, headers, redirect: "error", ...(body.length === 0 ? {} : { body: body.buffer as ArrayBuffer }) });
          const result = sanitizeUpstreamResponse(path, method, upstreamResponse);
          res.writeHead(result.status, Object.fromEntries(result.headers));
          res.end(Buffer.from(await result.arrayBuffer()));
          return;
        }
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
      if (process.env.SHARE_TRUST_BUNDLE === undefined && process.env.SHARE_TRUST_BUNDLE_FILE === undefined) {
        if (process.env.SHARE_DEPLOY_BUILD === "true") throw new Error("SHARE_TRUST_BUNDLE is required for deploy builds");
        return;
      }
      const bundle = loadTrustBundle();
      const publicConfig = { version: "tinycloud.share-email-claim/config-v1", shareOrigin: bundle.public.shareOrigin, registryOrigin: bundle.public.registryOrigin, nodeOrigin: bundle.public.nodeOrigin, credentialsOrigin: bundle.public.credentialsOrigin, nodeAudience: bundle.public.nodeAudience, nodeEnabled: bundle.public.nodeEnabled, issuerDid: bundle.public.issuerDid, issuerVct: bundle.public.issuerVct, issuerEnabled: bundle.public.issuerEnabled, nodeInvitationKid: bundle.public.nodeInvitationKid, nodeInvitationPublicKey: bundle.public.nodeInvitationPublicKey, nodeKeyVersion: bundle.public.nodeKeyVersion, issuerKeyVersion: bundle.public.issuerKeyVersion, issuerPublicKey: bundle.public.issuerPublicKey, ...(bundle.environment === "test" ? { environment: "test" as const } : {}) };
      this.emitFile({ type: "asset", fileName: ".well-known/tinycloud-share/config.json", source: `${JSON.stringify(publicConfig)}\n` });
      this.emitFile({ type: "asset", fileName: "_headers", source: cloudflareHeaders(bundle) });
    },
  };
}

function securityHeaders(): Plugin {
  const serve = (server: ViteDevServer | PreviewServer): void => {
    server.middlewares.use((req, res, next) => {
      try {
        const bundle = loadTrustBundle();
        const path = (req.url ?? "").split("?")[0] ?? "";
        for (const [name, value] of Object.entries(securityHeadersForPath(bundle, path))) res.setHeader(name, value);
      } catch (error) {
        if (process.env.SHARE_DEPLOY_STARTUP === "true") { res.writeHead(503, { "content-type": "application/json" }); res.end(JSON.stringify({ error: { code: "capability_unavailable" } })); return; }
        void error;
      }
      next();
    });
  };
  return { name: "share-security-headers", configureServer: serve, configurePreviewServer: serve };
}

const JSON_HEADERS = { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" };

export default defineConfig({
  base: "/",
  plugins: [shareRouteRewrite(), securityHeaders(), mermaidSandboxHtml(), shareHostAdapter()],
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
