import { afterEach, describe, expect, it, vi } from "vitest";
import { readFileSync } from "node:fs";
import { toBase64Url } from "@tinycloud/share-envelope";
import { onRequest } from "../functions/[[path]].js";
import { createShareHostFromEnv } from "../src/host/share-adapter.js";
import { createProductionHandler } from "../src/host/production-server.js";
import { cloudflareHeaders, validateTrustBundle } from "../src/host/trust-bundle.js";

const API_ORIGIN = "https://api.share.tinycloud.xyz";
const SHARE_ORIGIN = "https://share.tinycloud.xyz";

function trustBundle(): Record<string, unknown> {
  return {
    version: "tinycloud.share-email-trust-bundle/v1",
    shareOrigin: SHARE_ORIGIN,
    returnOrigin: SHARE_ORIGIN,
    registryOrigin: "https://registry.tinycloud.xyz",
    credentialsOrigin: "https://witness.credentials.org",
    nodeOrigin: "https://node.tinycloud.xyz",
    nodeAudience: "did:web:node.tinycloud.xyz",
    nodeInvitationKid: "did:web:node.tinycloud.xyz#invitation-key-1",
    nodeInvitationPublicKey: toBase64Url(new Uint8Array(32).fill(3)),
    nodeKeyVersion: 1,
    nodeEnabled: true,
    issuerDid: "did:web:issuer.credentials.org",
    issuerVct: "opencredentials.email/v1",
    issuerKid: "did:web:issuer.credentials.org#email-signing-key-1",
    issuerPublicKey: toBase64Url(new Uint8Array(32).fill(4)),
    issuerKeyVersion: 1,
    issuerEnabled: true,
  };
}

function pagesContext(path: string, options: { readonly method?: string; readonly origin?: string | undefined; readonly headers?: HeadersInit; readonly body?: string } = {}) {
  const method = options.method ?? "GET";
  const request = new Request(`${SHARE_ORIGIN}${path}`, {
    method,
    ...(options.headers === undefined ? {} : { headers: options.headers }),
    ...(["GET", "HEAD"].includes(method) ? {} : { body: options.body ?? "{}" }),
  });
  const next = vi.fn(async () => new Response("static asset", { status: 200 }));
  const env: { SHARE_API_ORIGIN?: string } = { SHARE_API_ORIGIN: options.origin ?? API_ORIGIN };
  return { context: { request, env, next }, next };
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("sender page boot state", () => {
  it("renders useful branded content before the application JavaScript loads", () => {
    const html = readFileSync("share.html", "utf8");
    const stylesheet = html.indexOf('<link rel="stylesheet" href="/src/email-share/sender.css">');
    const application = html.indexOf('<script type="module" src="/src/share/main.ts"></script>');
    expect(stylesheet).toBeGreaterThan(-1);
    expect(application).toBeGreaterThan(stylesheet);
    expect(html).toContain('<div id="share-app" tabindex="-1" aria-busy="true">');
    expect(html).toContain('aria-label="Preparing secure sign-in"');
    expect(html).toContain("Loading secure sign-in…");
  });
});

describe("Cloudflare Pages static asset boundaries", () => {
  it("ships a script-free top-level 404 page so missing modules are not rewritten to the app shell", () => {
    const html = readFileSync("public/404.html", "utf8");
    expect(html).toContain("<h1>Page not found.</h1>");
    expect(html).not.toMatch(/<script\b/i);
  });

  it("keeps entry documents fresh and content-hashed assets immutable", () => {
    for (const headers of [
      readFileSync("public/_headers", "utf8"),
      cloudflareHeaders(validateTrustBundle(trustBundle())),
    ]) {
      expect(headers).toMatch(/\/share\n(?:  .+\n)*  Cache-Control: no-store/);
      expect(headers).toMatch(/\/share\.html\n(?:  .+\n)*  Cache-Control: no-store/);
      expect(headers).toMatch(/\/assets\/\*\n  Cache-Control: public, max-age=31536000, immutable/);
      expect(headers).toMatch(/\/404\.html\n  Cache-Control: no-store/);
    }
  });

  it("converts the Pages SPA fallback into a real 404 for missing build assets", async () => {
    const { context, next } = pagesContext("/assets/missing-module.js");
    next.mockResolvedValue(new Response("<!doctype html><title>Landing</title>", {
      status: 200,
      headers: { "content-type": "text/html; charset=utf-8" },
    }));
    const response = await onRequest(context);
    expect(response.status).toBe(404);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(response.headers.get("x-content-type-options")).toBe("nosniff");
    expect(await response.text()).toBe("");
  });

  it("preserves real build assets and non-asset application routes", async () => {
    const asset = pagesContext("/assets/app.js");
    asset.next.mockResolvedValue(new Response("export const ready = true;", {
      headers: { "content-type": "application/javascript" },
    }));
    const assetResponse = await onRequest(asset.context);
    expect(assetResponse.status).toBe(200);
    expect(await assetResponse.text()).toBe("export const ready = true;");

    const page = pagesContext("/share");
    page.next.mockResolvedValue(new Response("<!doctype html><title>Share</title>", {
      headers: { "content-type": "text/html; charset=utf-8" },
    }));
    const pageResponse = await onRequest(page.context);
    expect(pageResponse.status).toBe(200);
    expect(await pageResponse.text()).toContain("<title>Share</title>");
  });
});

describe("production sender route gating", () => {
  it("blocks only the sender authorization route while recipient and registry routes still proxy", async () => {
    const raw = trustBundle();
    const bundle = validateTrustBundle(raw);
    const host = createShareHostFromEnv({ SHARE_TRUST_BUNDLE: JSON.stringify(raw) });
    const requests: Request[] = [];
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      requests.push(input instanceof Request ? input : new Request(input));
      return new Response("{}", { status: 200, headers: { "content-type": "application/json" } });
    });
    const handler = createProductionHandler({ bundle, host });
    const post = (path: string) => handler(new Request(`${SHARE_ORIGIN}${path}`, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" }));

    const sender = await post("/share/v1/invitations/authorize");
    expect(sender.status).toBe(503);
    expect(await sender.json()).toEqual({ error: { code: "sender_not_ready" } });
    expect(requests).toHaveLength(0);

    for (const path of [
      "/share/v1/policy/challenges",
      "/share/v1/policy/session",
      "/share/v1/read",
      "/v1/share-email/claims/challenge",
      "/v1/share-email/claims/redeem",
    ]) expect((await post(path)).status).toBe(200);
    expect((await handler(new Request(`${SHARE_ORIGIN}/registry`))).status).toBe(200);
    expect((await handler(new Request(`${SHARE_ORIGIN}/registry/blobs/bafkreiabc?download=1`))).status).toBe(200);

    expect(requests.map((request) => new URL(request.url).pathname)).toEqual([
      "/share/v1/policy/challenges",
      "/share/v1/policy/session",
      "/share/v1/read",
      "/v1/share-email/claims/challenge",
      "/v1/share-email/claims/redeem",
      "/",
      "/blobs/bafkreiabc",
    ]);
  });
});

describe("Cloudflare Pages API proxy", () => {
  it.each([
    undefined,
    "",
    ` ${API_ORIGIN}`,
    `${API_ORIGIN} `,
    `${API_ORIGIN}:444`,
    "https://user@api.share.tinycloud.xyz",
    `${API_ORIGIN}/path`,
    `${API_ORIGIN}?query=1`,
    `${API_ORIGIN}#fragment`,
    "http://api.share.tinycloud.xyz",
    "https://API.share.tinycloud.xyz",
  ])("rejects every non-literal API origin (%s)", async (origin) => {
    const fetched = vi.spyOn(globalThis, "fetch");
    const { context } = pagesContext("/health/readiness", { origin });
    if (origin === undefined) context.env = {};
    const response = await onRequest(context);
    expect(response.status).toBe(503);
    expect(fetched).not.toHaveBeenCalled();
  });

  it("preserves the browser session boundary and strips upstream implementation headers", async () => {
    let proxied: Request | undefined;
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      proxied = input instanceof Request ? input : new Request(input);
      return new Response(JSON.stringify({ ok: true }), { headers: { "content-type": "application/json", "set-cookie": "share_session=opaque; Secure; HttpOnly; Path=/", server: "private", via: "private-proxy" } });
    });
    const { context } = pagesContext("/api/share/auth/openkey?flow=callback", {
      method: "POST",
      headers: { origin: SHARE_ORIGIN, host: "evil.example", cookie: "share_session=incoming", "content-type": "application/json" },
      body: "{}",
    });
    const response = await onRequest(context);
    expect(response.status).toBe(200);
    expect(proxied).toBeDefined();
    expect(proxied!.url).toBe(`${API_ORIGIN}/api/share/auth/openkey?flow=callback`);
    expect(new URL(proxied!.url).host).toBe("api.share.tinycloud.xyz");
    expect(proxied!.method).toBe("POST");
    expect(proxied!.redirect).toBe("manual");
    expect(proxied!.headers.get("origin")).toBe(SHARE_ORIGIN);
    expect(proxied!.headers.has("host")).toBe(false);
    expect(proxied!.headers.get("cookie")).toBe("share_session=incoming");
    expect(response.headers.get("set-cookie")).toContain("share_session=opaque");
    expect(response.headers.has("server")).toBe(false);
    expect(response.headers.has("via")).toBe(false);
  });

  it("routes exact and child registry paths but falls through for lookalikes and static paths", async () => {
    const targets: string[] = [];
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      targets.push((input instanceof Request ? input : new Request(input)).url);
      return new Response("{}", { headers: { "content-type": "application/json" } });
    });
    for (const path of ["/registry", "/registry/", "/registry/blobs/cid", "/api/share/link-only/registry/blobs"]) {
      const { context, next } = pagesContext(path);
      expect((await onRequest(context)).status).toBe(200);
      expect(next).not.toHaveBeenCalled();
    }
    for (const path of ["/registry-lookalike", "/assets/app.js", "/share"]) {
      const { context, next } = pagesContext(path);
      expect(await (await onRequest(context)).text()).toBe("static asset");
      expect(next).toHaveBeenCalledOnce();
    }
    expect(targets).toEqual([`${API_ORIGIN}/registry`, `${API_ORIGIN}/registry/`, `${API_ORIGIN}/registry/blobs/cid`, `${API_ORIGIN}/api/share/link-only/registry/blobs`]);
  });

  it("fails closed for unsupported methods, redirects, and fetch failures", async () => {
    const invalid = pagesContext("/registry").context;
    invalid.request = { url: `${SHARE_ORIGIN}/registry`, method: "PURGE", headers: new Headers(), body: null } as Request;
    expect((await onRequest(invalid)).status).toBe(405);

    vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(new Response(null, { status: 302, headers: { location: "https://evil.example" } }));
    expect((await onRequest(pagesContext("/registry").context)).status).toBe(502);

    vi.mocked(globalThis.fetch).mockRejectedValueOnce(new Error("offline"));
    expect((await onRequest(pagesContext("/registry").context)).status).toBe(502);
  });
});
