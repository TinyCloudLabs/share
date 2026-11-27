/**
 * The JSX runtime's module files: the one table shared by the build (build.ts),
 * the viewer's loader (../../viewer/jsx-modules.ts) and the frame (runtime.ts).
 *
 * Every file is a classic-script text that registers one or more import
 * specifiers with the frame's require shim (`__TC_DEFINE__`, see
 * ../../viewer/jsx-frame.ts). Registration is lazy: a factory runs on the first
 * `require`, so the order the bridge inlines the files in does not matter and
 * React is one shared instance.
 */

/** Directory (URL path and file path) of the library files and manifest. Names no host. */
export const JSX_RUNTIME_ASSET_DIR = "assets/jsx-runtime";
export const JSX_RUNTIME_URL_PREFIX = `/${JSX_RUNTIME_ASSET_DIR}/`;

export interface JsxModuleSpec {
  /** File id: the key in the render message's `modules` map and the manifest. */
  readonly id: string;
  /** Import specifiers this file answers. */
  readonly provides: readonly string[];
  /** `true` for the files every render receives; the rest are sent only when imported. */
  readonly always: boolean;
}

export const JSX_MODULE_SPECS: readonly JsxModuleSpec[] = [
  { id: "react", provides: ["react", "react/jsx-runtime", "react/jsx-dev-runtime"], always: true },
  { id: "react-dom", provides: ["react-dom", "react-dom/client"], always: true },
  { id: "runtime", provides: ["@tc/runtime"], always: true },
  { id: "tailwind", provides: ["@tailwindcss/browser"], always: true },
  { id: "lucide-react", provides: ["lucide-react"], always: false },
  { id: "recharts", provides: ["recharts"], always: false },
  { id: "d3", provides: ["d3"], always: false },
  { id: "mermaid", provides: ["mermaid"], always: false },
];

/** What the unknown-import panel lists. Internal specifiers (`@tc/*`, tailwind) are not offered. */
export const JSX_LIBRARY_SET: readonly string[] = [
  "react",
  "react-dom",
  "react-dom/client",
  "react/jsx-runtime",
  "lucide-react",
  "recharts",
  "d3",
  "mermaid",
];

export interface JsxManifestFile {
  readonly id: string;
  /** Same-origin URL; the file name carries a content hash. */
  readonly url: string;
  /** Lowercase hex sha256 of the file text (UTF-8). The only trust anchor for the text. */
  readonly sha256: string;
  readonly bytes: number;
  readonly provides: readonly string[];
}

export interface JsxManifest {
  readonly version: 1;
  readonly files: Readonly<Record<string, JsxManifestFile>>;
}

/** Maps an import specifier to the file id that answers it. */
export function fileIdForSpecifier(manifest: JsxManifest, specifier: string): string | undefined {
  for (const file of Object.values(manifest.files)) {
    if (file.provides.includes(specifier)) return file.id;
  }
  return undefined;
}
