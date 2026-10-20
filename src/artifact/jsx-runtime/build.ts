/**
 * Build-time only (Node). Produces the JSX runtime module files, their sha256
 * manifest and the third-party notice, for the Vite plugin (vite.config.ts) and
 * the NOTICE generator (scripts/generate-jsx-notice.mts).
 *
 * Each file is bundled by esbuild as CommonJS and wrapped as
 *
 *   __TC_DEFINE__(["spec", …], function (module, exports, require) { … });
 *
 * so it registers lazily with the frame's require shim. React, react-dom and
 * the runtime are separate files; libraries mark `react*` external, which makes
 * every library `require("react")` the one shared instance at run time.
 * No file contains `</script` or `<!--`: the bridge inlines the text into a
 * classic `<script>`, and this module refuses to emit a file that could end it.
 */
import { createHash } from "node:crypto";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { build, type BuildOptions, type Metafile } from "esbuild";

import { JSX_MODULE_SPECS, JSX_RUNTIME_ASSET_DIR, type JsxManifest, type JsxManifestFile, type JsxModuleSpec } from "./files.js";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
const ENTRIES = join(ROOT, "src/artifact/jsx-runtime/entries");

/** Permissive licences only. An SPDX `OR` passes if any alternative is allowed, `AND` needs all. */
export const ALLOWED_LICENCES: Readonly<Record<string, true>> = {
  "MIT": true,
  "ISC": true,
  "Apache-2.0": true,
  "BSD-2-Clause": true,
  "BSD-3-Clause": true,
  "0BSD": true,
};

/**
 * Packages that ship a licence file but declare no `license` field. The text is
 * read and must contain the marker, so a changed licence fails the build.
 */
const UNDECLARED_LICENCE: Readonly<Record<string, { readonly licence: string; readonly marker: string }>> = {
  khroma: { licence: "MIT", marker: "The MIT License" },
};

export interface BundledPackage {
  readonly name: string;
  readonly version: string;
  /** SPDX expression as published. */
  readonly licence: string;
  /** The alternative relied on when the published expression offers a choice. */
  readonly effectiveLicence: string;
  /** Verbatim LICENSE/COPYING text, or `undefined` when the package ships none. */
  readonly licenceText: string | undefined;
  /** Author/source lines from package.json, printed when the package ships no licence file. */
  readonly provenance: string;
  /** Module files this package is bundled into. */
  readonly files: readonly string[];
  /** Set when the code is pre-bundled inside another package's dist rather than installed. */
  readonly embeddedIn?: string;
}

export interface BuiltJsxFile extends JsxManifestFile {
  readonly text: string;
  readonly fileName: string;
}

export interface JsxRuntimeBuild {
  readonly files: readonly BuiltJsxFile[];
  readonly manifest: JsxManifest;
  readonly packages: readonly BundledPackage[];
}

const REACT_EXTERNAL = ["react", "react/*"];
const REACT_DOM_EXTERNAL = ["react", "react/*", "react-dom", "react-dom/*"];

interface Bundle {
  readonly code: string;
  readonly inputs: readonly string[];
}

async function bundle(options: BuildOptions): Promise<Bundle> {
  const result = await build({
    absWorkingDir: ROOT,
    bundle: true,
    write: false,
    metafile: true,
    format: "cjs",
    platform: "browser",
    target: "es2020",
    minify: true,
    legalComments: "none",
    logLevel: "silent",
    define: { "process.env.NODE_ENV": '"production"' },
    ...options,
  });
  const output = result.outputFiles?.[0];
  const meta: Metafile | undefined = result.metafile;
  if (output === undefined || meta === undefined) throw new Error("esbuild produced no output");
  const outputMeta = Object.values(meta.outputs)[0];
  // Only inputs that contribute bytes after tree-shaking are bundled code.
  const inputs = Object.entries(outputMeta?.inputs ?? {})
    .filter(([, info]) => info.bytesInOutput > 0)
    .map(([path]) => path);
  return { code: output.text, inputs };
}

/**
 * d3 without `d3-delaunay`: its dependency `robust-predicates` is Unlicense,
 * outside the permissive-licence policy. Everything else d3 exports is kept.
 */
function d3EntrySource(): string {
  const index = readFileSync(join(ROOT, "node_modules/d3/src/index.js"), "utf8");
  return index
    .split("\n")
    .filter((line) => !line.includes("d3-delaunay"))
    .join("\n");
}

function fileEntry(spec: JsxModuleSpec): BuildOptions {
  const entry = (name: string): string => join(ENTRIES, name);
  switch (spec.id) {
    case "react":
      return { entryPoints: [entry("react.mjs")] };
    case "react-dom":
      return { entryPoints: [entry("react-dom.mjs")], external: REACT_EXTERNAL };
    case "runtime":
      return {
        entryPoints: [join(ROOT, "src/artifact/jsx-runtime/runtime.ts")],
        external: REACT_DOM_EXTERNAL,
      };
    case "lucide-react":
      return { entryPoints: [entry("lucide-react.mjs")], external: REACT_DOM_EXTERNAL };
    case "recharts":
      return { entryPoints: [entry("recharts.mjs")], external: REACT_DOM_EXTERNAL };
    case "mermaid":
      return { entryPoints: [entry("mermaid.mjs")] };
    case "tinycloud-app":
      // No dependencies: a thin postMessage client (app-module.ts).
      return { entryPoints: [join(ROOT, "src/artifact/jsx-runtime/app-module.ts")] };
    case "d3":
      return {
        stdin: { contents: d3EntrySource(), resolveDir: join(ROOT, "node_modules/d3/src"), sourcefile: "d3-index.js", loader: "js" },
      };
    default:
      throw new Error(`no entry for jsx module ${spec.id}`);
  }
}

/**
 * In bundled libraries these sequences occur only inside string and regex
 * literals (DOMPurify's `"<!-->"`, marked's comment regex). `\/` and `\x21`
 * are valid there, including in `u`-flag regexes, and spell the same characters.
 * assertInlineSafe fails the build if one remains anywhere else.
 */
function defang(code: string): string {
  return code.replace(/<\/(script)/gi, "<\\/$1").replace(/<!--/g, "<\\x21--");
}

function wrap(provides: readonly string[], code: string): string {
  return `__TC_DEFINE__(${JSON.stringify(provides)},function(module,exports,require){${defang(code)}\n});\n`;
}

interface PackageLocation {
  readonly dir: string;
  /** Set for a copy vendored inside another package (victory-vendor/lib-vendor/<d3-…>). */
  readonly vendoredIn?: string;
}

function packageLocationOf(inputPath: string): PackageLocation | undefined {
  const marker = "node_modules/";
  const at = inputPath.lastIndexOf(marker);
  if (at < 0) return undefined;
  const rest = inputPath.slice(at + marker.length).split("/");
  const name = rest[0]?.startsWith("@") ? `${rest[0]}/${rest[1] ?? ""}` : rest[0];
  if (name === undefined || name === "") return undefined;
  const dir = join(ROOT, inputPath.slice(0, at + marker.length), name);
  const vendored = /^lib-vendor\/([^/]+)\//.exec(inputPath.slice(at + marker.length + name.length + 1));
  return vendored?.[1] === undefined ? { dir } : { dir: join(dir, "lib-vendor", vendored[1]), vendoredIn: dir };
}

/** SPDX id of a licence file that ships without a package.json, from its standard wording. */
function detectLicence(text: string | undefined): string | undefined {
  if (text === undefined) return undefined;
  if (/Permission is hereby granted, free of charge/i.test(text)) return "MIT";
  if (/Permission to use, copy, modify, and\/or distribute this software for any purpose with or without fee/i.test(text)) return "ISC";
  if (/Redistribution and use in source and binary forms/i.test(text) && /Neither the name of/i.test(text)) return "BSD-3-Clause";
  return undefined;
}

function licenceTextOf(dir: string): string | undefined {
  const file = readdirSync(dir).find((entry) => /^(licen[cs]e|copying)(\.|$)/i.test(entry));
  if (file !== undefined) return readFileSync(join(dir, file), "utf8").trim();
  return readmeLicenceSection(dir);
}

/** Packages that ship no licence file but print the full licence text in their README (fastdom). */
function readmeLicenceSection(dir: string): string | undefined {
  const readme = readdirSync(dir).find((entry) => /^readme(\.md)?$/i.test(entry));
  if (readme === undefined) return undefined;
  const text = readFileSync(join(dir, readme), "utf8");
  const heading = /^#+[ \t]*licen[cs]es?[ \t]*$/im.exec(text);
  if (heading === null) return undefined;
  const rest = text.slice(heading.index + heading[0].length);
  const next = /^#+[ \t]/m.exec(rest);
  const section = (next === null ? rest : rest.slice(0, next.index)).trim();
  return /Permission is hereby granted/i.test(section)
    ? `(From the "License" section of the package README; the package ships no licence file.)\n\n${section}`
    : undefined;
}

/**
 * Packages whose own licence text is incomplete: a committed copy of the upstream
 * licence, and/or the licence files of copies vendored inside the package.
 */
const SUPPLEMENTAL_LICENCES: Readonly<Record<string, { readonly file?: string; readonly vendoredDir?: string }>> = {
  "victory-vendor": { file: "licences/victory-vendor.txt", vendoredDir: "lib-vendor" },
};

function supplementalLicenceText(name: string, dir: string): string | undefined {
  const entry = SUPPLEMENTAL_LICENCES[name];
  if (entry === undefined) return undefined;
  const parts: string[] = [];
  if (entry.file !== undefined) parts.push(readFileSync(join(ROOT, "src/artifact/jsx-runtime", entry.file), "utf8").trim());
  if (entry.vendoredDir !== undefined) {
    const base = join(dir, entry.vendoredDir);
    const heading = `Licence files shipped in ${name}/${entry.vendoredDir}/ (vendored copies; the bundle uses the installed d3 packages listed above):`;
    const vendored = readdirSync(base).sort().flatMap((child) => {
      const text = existsSync(join(base, child)) ? licenceTextOf(join(base, child)) : undefined;
      return text === undefined ? [] : [`--- ${child} ---\n${text}`];
    });
    if (vendored.length > 0) parts.push([heading, ...vendored].join("\n\n"));
  }
  return parts.length === 0 ? undefined : parts.join("\n\n");
}

function declaredLicence(manifest: Record<string, unknown>): string | undefined {
  const { license, licenses } = manifest;
  if (typeof license === "string") return license;
  if (typeof license === "object" && license !== null && "type" in license && typeof license.type === "string") return license.type;
  if (Array.isArray(licenses)) {
    const types = licenses.flatMap((entry: unknown) =>
      typeof entry === "object" && entry !== null && "type" in entry && typeof entry.type === "string" ? [entry.type] : []);
    if (types.length > 0) return types.join(" OR ");
  }
  return undefined;
}

/** Returns the allowed alternative an SPDX expression rests on, or `undefined` if none is allowed. */
export function effectiveLicence(expression: string): string | undefined {
  const cleaned = expression.replace(/[()]/g, " ").trim();
  const alternatives = cleaned.split(/\s+OR\s+/i);
  for (const alternative of alternatives) {
    const terms = alternative.split(/\s+AND\s+/i).map((term) => term.trim());
    if (terms.every((term) => Object.hasOwn(ALLOWED_LICENCES, term))) return terms.join(" AND ");
  }
  return undefined;
}

function collectPackages(perFile: ReadonlyMap<string, readonly string[]>): BundledPackage[] {
  const byDir = new Map<string, { location: PackageLocation; files: Set<string> }>();
  for (const [fileId, inputs] of perFile) {
    for (const input of inputs) {
      const location = packageLocationOf(input);
      if (location === undefined) continue;
      const entry = byDir.get(location.dir) ?? { location, files: new Set<string>() };
      entry.files.add(fileId);
      byDir.set(location.dir, entry);
    }
  }
  const packages: BundledPackage[] = [];
  const rejected: string[] = [];
  for (const [dir, { location, files }] of byDir) {
    const ownText = licenceTextOf(dir);
    const ownManifest = join(dir, "package.json");
    const manifestPath = existsSync(ownManifest) ? ownManifest : join(location.vendoredIn ?? dir, "package.json");
    const parsed: unknown = JSON.parse(readFileSync(manifestPath, "utf8"));
    if (typeof parsed !== "object" || parsed === null) throw new Error(`unreadable package.json in ${dir}`);
    const record = parsed as Record<string, unknown>;
    const hostName = typeof record["name"] === "string" ? record["name"] : dir;
    const hostVersion = typeof record["version"] === "string" ? record["version"] : "0.0.0";
    const name = location.vendoredIn === undefined ? hostName : `${dir.split("/").at(-1)} (vendored in ${hostName})`;
    const version = hostVersion;
    const supplemental = location.vendoredIn === undefined ? supplementalLicenceText(hostName, dir) : undefined;
    const licenceText = supplemental === undefined ? ownText : [ownText, supplemental].filter((part): part is string => part !== undefined).join("\n\n");
    const undeclared = UNDECLARED_LICENCE[hostName];
    const licence = location.vendoredIn !== undefined
      ? detectLicence(licenceText)
      : declaredLicence(record)
        ?? (undeclared !== undefined && licenceText?.includes(undeclared.marker) === true ? undeclared.licence : undefined);
    const effective = licence === undefined ? undefined : effectiveLicence(licence);
    if (licence === undefined || effective === undefined) {
      rejected.push(`${name}@${version} (${licence ?? "no licence declared"})`);
      continue;
    }
    const origin = record["repository"];
    const author = record["author"];
    const authorName = typeof author === "string" ? author : typeof author === "object" && author !== null && "name" in author && typeof author.name === "string" ? author.name : undefined;
    const provenance = [authorName === undefined ? undefined : `Author: ${authorName}`, typeof origin === "object" && origin !== null && "url" in origin && typeof origin.url === "string" ? `Source: ${origin.url}` : undefined]
      .filter((line): line is string => line !== undefined).join("\n");
    packages.push({ name, version, licence, effectiveLicence: effective, licenceText, provenance, files: [...files].sort() });
  }
  if (rejected.length > 0) throw new Error(`bundled packages outside the permissive-licence policy: ${rejected.join(", ")}`);
  return packages.sort((x, y) => x.name.localeCompare(y.name) || x.version.localeCompare(y.version));
}

interface EmbeddedLicence {
  readonly name: string;
  readonly version: string;
  readonly licence: string;
  readonly text: string;
}

/**
 * Code a dependency pre-bundled into its own dist (`@mermaid-js/parser` inlines
 * langium, chevrotain and the vscode protocol packages). Esbuild sees one file, so
 * the metafile names only the host. The embedded packages are read from the host's
 * source maps, and each must have a committed licence text (licences/embedded.json):
 * a new one fails the build until its licence is added and checked.
 */
function collectEmbedded(inputs: readonly string[], installed: readonly BundledPackage[]): BundledPackage[] {
  const known: { readonly packages: readonly EmbeddedLicence[] } = JSON.parse(readFileSync(join(ROOT, "src/artifact/jsx-runtime/licences/embedded.json"), "utf8"));
  const found = new Map<string, string>();
  for (const input of inputs) {
    if (!/node_modules\/@mermaid-js\/parser\/dist\//.test(input) || !existsSync(join(ROOT, `${input}.map`))) continue;
    const map: { sources?: unknown } = JSON.parse(readFileSync(join(ROOT, `${input}.map`), "utf8"));
    for (const source of Array.isArray(map.sources) ? map.sources : []) {
      const match = typeof source === "string" ? /node_modules\/\.pnpm\/((?:@[^+/]+\+)?[^@/]+)@([^/_]+)/.exec(source) : null;
      if (match?.[1] !== undefined && match[2] !== undefined) found.set(`${match[1].replace("+", "/")}@${match[2]}`, "@mermaid-js/parser");
    }
  }
  const have = new Set(installed.map((pkg) => `${pkg.name}@${pkg.version}`));
  const result: BundledPackage[] = [];
  const missing: string[] = [];
  for (const [key, host] of found) {
    if (have.has(key)) continue;
    const entry = known.packages.find((candidate) => `${candidate.name}@${candidate.version}` === key);
    const effective = entry === undefined ? undefined : effectiveLicence(entry.licence);
    if (entry === undefined || effective === undefined) { missing.push(key); continue; }
    result.push({ name: entry.name, version: entry.version, licence: entry.licence, effectiveLicence: effective, licenceText: entry.text, provenance: "", files: ["mermaid"], embeddedIn: host });
  }
  if (missing.length > 0) throw new Error(`embedded packages without an allowed, committed licence (licences/embedded.json): ${missing.join(", ")}`);
  return result;
}

function assertInlineSafe(id: string, text: string): void {
  if (/<\/script/i.test(text) || /<!--/.test(text)) {
    throw new Error(`jsx module ${id} contains "</script" or "<!--" and cannot be inlined into a script element`);
  }
}

export async function buildJsxRuntime(): Promise<JsxRuntimeBuild> {
  const files: BuiltJsxFile[] = [];
  const inputsByFile = new Map<string, readonly string[]>();
  for (const spec of JSX_MODULE_SPECS) {
    let text: string;
    if (spec.id === "tailwind") {
      // Already a self-contained script; wrapped so it starts when the runtime requires it.
      const path = join(ROOT, "node_modules/@tailwindcss/browser/dist/index.global.js");
      text = wrap(spec.provides, readFileSync(path, "utf8"));
      inputsByFile.set(spec.id, ["node_modules/@tailwindcss/browser/dist/index.global.js"]);
    } else {
      const { code, inputs } = await bundle(fileEntry(spec));
      text = wrap(spec.provides, code);
      inputsByFile.set(spec.id, inputs);
    }
    assertInlineSafe(spec.id, text);
    const sha256 = createHash("sha256").update(text, "utf8").digest("hex");
    const fileName = `${JSX_RUNTIME_ASSET_DIR}/${spec.id}.${sha256.slice(0, 10)}.js`;
    files.push({ id: spec.id, provides: spec.provides, url: `/${fileName}`, sha256, bytes: Buffer.byteLength(text, "utf8"), text, fileName });
  }
  const manifest: JsxManifest = {
    version: 1,
    files: Object.fromEntries(files.map(({ id, url, sha256, bytes, provides }) => [id, { id, url, sha256, bytes, provides }])),
  };
  const installed = collectPackages(inputsByFile);
  const embedded = collectEmbedded([...inputsByFile.values()].flat(), installed);
  const packages = [...installed, ...embedded].sort((a, b) => a.name.localeCompare(b.name) || a.version.localeCompare(b.version));
  return { files, manifest, packages };
}

/** NOTICE text: every bundled package with its licence, verbatim where the package ships one. */
export function renderNotice(packages: readonly BundledPackage[]): string {
  const lines: string[] = [
    "NOTICE: third-party software bundled with the Share JSX runtime",
    "",
    "The JSX artifact renderer ships these packages as lazily loaded files served",
    "from this site (assets/jsx-runtime/). They run only inside the sandboxed",
    "artifact frame. Generated by scripts/generate-jsx-notice.mts from the esbuild",
    "metafile of the build; do not edit by hand. Licence policy: MIT, ISC,",
    "Apache-2.0, BSD-2-Clause, BSD-3-Clause and 0BSD only.",
    "",
    "The d3 library file is built without d3-delaunay (its dependency",
    "robust-predicates is Unlicense, outside that policy). d3-delaunay (ISC) is",
    "listed below because mermaid's own bundle includes it; no robust-predicates",
    "code is in any shipped file (the build test checks).",
    "",
    "@tailwindcss/browser's global build embeds the tailwindcss core, which carries",
    "the same MIT licence and copyright holder as the package listed below.",
    "",
    `Packages (${packages.length}):`,
    "",
  ];
  for (const pkg of packages) {
    const note = pkg.effectiveLicence === pkg.licence ? "" : `, used under ${pkg.effectiveLicence}`;
    const where = pkg.embeddedIn === undefined ? "" : `  (inlined in ${pkg.embeddedIn}'s dist)`;
    lines.push(`  ${pkg.name}@${pkg.version}  ${pkg.licence}${note}${where}`);
  }
  for (const pkg of packages) {
    lines.push("", "=".repeat(78), `${pkg.name}@${pkg.version}  (${pkg.licence}${pkg.effectiveLicence === pkg.licence ? "" : `, used under ${pkg.effectiveLicence}`}${pkg.embeddedIn === undefined ? "" : `; inlined in ${pkg.embeddedIn}'s dist`})`, "=".repeat(78), "");
    lines.push(pkg.licenceText ?? `This package ships no licence file; it declares ${pkg.licence} in its package.json.${pkg.provenance === "" ? "" : `\n${pkg.provenance}`}`);
  }
  return `${lines.join("\n")}\n`;
}
