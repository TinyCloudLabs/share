/**
 * Viewer side of the library set: which module files a JSX source needs, and
 * the verified texts of those files.
 *
 * The viewer NEVER parses or evaluates the artifact. It runs a bounded,
 * string-only regex scan for import specifiers; a name it does not know is
 * simply not sent, and the frame's require shim rejects it (the frame, not the
 * viewer, tells the author "x isn't in the library set"). Module texts come
 * only from the build's same-origin files and are accepted only when their
 * sha256 equals the build-time manifest's digest, so a truncated, stale or
 * swapped file is refused before any byte reaches the frame.
 */
import { JSX_MODULE_SPECS, JSX_RUNTIME_URL_PREFIX, fileIdForSpecifier, type JsxManifest } from "../artifact/jsx-runtime/files.js";
import { USER_CONTENT_ORIGIN, userContentUrl } from "./user-content-origin.js";

const MAX_SPECIFIERS = 100;

const SCANS: readonly RegExp[] = [
  // import a, { b } from "x"   /   export * from "x"   /   export { a } from "x"
  /\b(?:import|export)\b[^'"`;()]{0,2000}?\bfrom\s*["']([^"'\n]{1,200})["']/g,
  // import "x"
  /\bimport\s*["']([^"'\n]{1,200})["']/g,
  // require("x")   /   import("x")
  /\b(?:require|import)\s*\(\s*["']([^"'\n]{1,200})["']\s*\)/g,
];

/** Import specifiers a source mentions, in first-seen order. Never evaluates anything. */
export function scanImportSpecifiers(source: string): string[] {
  const found = new Set<string>();
  for (const pattern of SCANS) {
    for (const match of source.matchAll(pattern)) {
      const specifier = match[1];
      if (specifier !== undefined) found.add(specifier);
      if (found.size >= MAX_SPECIFIERS) return [...found];
    }
  }
  return [...found];
}

export class JsxModuleIntegrityError extends Error {
  readonly fileId: string;
  constructor(fileId: string, reason: string) {
    super(`jsx module ${fileId} refused: ${reason}`);
    this.name = "JsxModuleIntegrityError";
    this.fileId = fileId;
  }
}

/** File ids a render needs: every always-present file plus one per known imported specifier. */
export function requiredFileIds(manifest: JsxManifest, specifiers: readonly string[], allowRunnerModules = false): string[] {
  const ids = new Set<string>(JSX_MODULE_SPECS.filter((spec) => spec.always).map((spec) => spec.id));
  for (const specifier of specifiers) {
    const id = fileIdForSpecifier(manifest, specifier, allowRunnerModules);
    if (id !== undefined) ids.add(id);
  }
  return [...ids];
}

function hex(bytes: ArrayBuffer): string {
  return Array.from(new Uint8Array(bytes), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export interface LoadModulesOptions {
  readonly fetch?: typeof fetch;
  /** Where the library files are served from; defaults to the build's user-content origin. */
  readonly userContentOrigin?: string;
  /** The installed-app runner only: also load the `@tinycloud/app` client when the source imports it. */
  readonly allowRunnerModules?: boolean;
}

/**
 * Fetches the files `source` needs and returns `{[fileId]: text}`. Rejects with
 * JsxModuleIntegrityError when any file's digest differs from the manifest.
 */
export async function loadJsxModules(manifest: JsxManifest, source: string, options: LoadModulesOptions = {}): Promise<Record<string, string>> {
  const fetchImpl = options.fetch ?? globalThis.fetch.bind(globalThis);
  const origin = options.userContentOrigin ?? USER_CONTENT_ORIGIN;
  const ids = requiredFileIds(manifest, scanImportSpecifiers(source), options.allowRunnerModules === true);
  const entries = await Promise.all(ids.map(async (id): Promise<[string, string]> => {
    const file = manifest.files[id];
    if (file === undefined) throw new JsxModuleIntegrityError(id, "not in the build manifest");
    if (!file.url.startsWith(JSX_RUNTIME_URL_PREFIX) || file.url.includes("..")) throw new JsxModuleIntegrityError(id, "unexpected location");
    // CORS, no credentials, no referrer: a cross-origin host sees an anonymous GET and
    // answers only the viewer origin. The digest below, not the host, is the trust anchor.
    let response: Response;
    try {
      response = await fetchImpl(userContentUrl(file.url, origin), { mode: "cors", credentials: "omit", referrerPolicy: "no-referrer" });
    } catch {
      throw new JsxModuleIntegrityError(id, "unreachable");
    }
    if (!response.ok) throw new JsxModuleIntegrityError(id, `HTTP ${response.status}`);
    const bytes = await response.arrayBuffer();
    if (bytes.byteLength !== file.bytes) throw new JsxModuleIntegrityError(id, "size differs from the manifest");
    // A typed-array view (no copy): some runtimes (Node 20 under jsdom) reject a bare ArrayBuffer from fetch.
    if (hex(await crypto.subtle.digest("SHA-256", new Uint8Array(bytes))) !== file.sha256) throw new JsxModuleIntegrityError(id, "sha256 differs from the manifest");
    return [id, new TextDecoder("utf-8", { fatal: true }).decode(bytes)];
  }));
  return Object.fromEntries(entries);
}
