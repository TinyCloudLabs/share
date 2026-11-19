/**
 * TinyCloud One's origins by build kind (One Apps embed contract v1, "Origins").
 *
 * The kind is decided at build time and fails closed: production unless an
 * explicit signal says otherwise. Production names only tinycloud.one. A
 * pages.dev preview origin is controlled by whoever can push a branch there,
 * and localhost by anyone on the machine, so neither may reach a production
 * build's header or bundle.
 *
 * The build signal is `VITE_ONE_BUILD`: only the exact value "preview" selects
 * preview. `vite` (the dev server) is the dev kind. Pure strings and functions
 * (no Node or browser APIs) so the vite config, the embed controller and the
 * tests share them.
 */
export const ONE_PRODUCTION_ORIGIN = "https://tinycloud.one";
export const ONE_PREVIEW_ORIGIN = "https://feat-one-apps.tinychat.pages.dev";
export const ONE_DEV_ORIGIN = "https://localhost:5190";

/** Name of the build signal; the value "preview" (exactly) adds the preview origin. */
export const ONE_BUILD_ENV = "VITE_ONE_BUILD";

export type BuildKind = "production" | "preview" | "dev";

export function buildKindOf(signals: { readonly dev?: boolean; readonly oneBuild?: unknown }): BuildKind {
  if (signals.dev === true) return "dev";
  return signals.oneBuild === "preview" ? "preview" : "production";
}

/** The parent origins the app accepts for a build kind. */
export function oneOriginsFor(kind: BuildKind): string[] {
  switch (kind) {
    case "production": return [ONE_PRODUCTION_ORIGIN];
    case "preview": return [ONE_PRODUCTION_ORIGIN, ONE_PREVIEW_ORIGIN];
    case "dev": return [ONE_PRODUCTION_ORIGIN, ONE_DEV_ORIGIN];
  }
}

/**
 * `frame-ancestors` sources for the framed routes: One's origins only. Share
 * itself frames no Courier page, so there is no 'self'. Dev servers serve no
 * `_headers`, so dev adds nothing.
 */
export function frameAncestorsFor(kind: BuildKind): string[] {
  return oneOriginsFor(kind === "dev" ? "production" : kind);
}

/** The routes One frames: /courier, /courier/ and everything below it. */
export const COURIER_FRAMED_ROUTES: readonly string[] = ["/courier", "/courier/", "/courier/*"];

/**
 * Rewrites the `frame-ancestors` directive of the framed routes' policies in a
 * `_headers` file. Every other section is returned untouched.
 */
export function renderCourierFrameHeaders(template: string, kind: BuildKind): string {
  const value = `frame-ancestors ${frameAncestorsFor(kind).join(" ")}`;
  return template.split(/(\n{2,})/).map((part) => {
    const route = part.split("\n", 1)[0]?.trim() ?? "";
    if (!COURIER_FRAMED_ROUTES.includes(route)) return part;
    return part.replace(/^(\s+Content-Security-Policy: .*?)frame-ancestors [^;\n]*$/m, (_line, before: string) => `${before}${value}`);
  }).join("");
}
