import { fileURLToPath } from "node:url";

import { defineConfig, type Plugin } from "vite";

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

export default defineConfig({
  base: "/",
  plugins: [shareRouteRewrite()],
  build: {
    rollupOptions: {
      input: {
        main: fileURLToPath(new URL("index.html", import.meta.url)),
        viewer: fileURLToPath(new URL("viewer.html", import.meta.url)),
      },
    },
  },
});
