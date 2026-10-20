// @vitest-environment node
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import vm from "node:vm";

import { beforeAll, describe, expect, it } from "vitest";

import { ALLOWED_LICENCES, buildJsxRuntime, effectiveLicence, renderNotice, type JsxRuntimeBuild } from "../src/artifact/jsx-runtime/build.js";
import { JSX_MODULE_SPECS } from "../src/artifact/jsx-runtime/files.js";
import { JSX_CHILD_PREAMBLE } from "../src/viewer/jsx-frame.js";

let built: JsxRuntimeBuild;
beforeAll(async () => { built = await buildJsxRuntime(); }, 120_000);

describe("JSX runtime build", () => {
  it("emits one content-hashed file per module, and the manifest digests are the file digests", () => {
    expect(built.files.map((file) => file.id)).toEqual(JSX_MODULE_SPECS.map((spec) => spec.id));
    for (const file of built.files) {
      const digest = createHash("sha256").update(file.text, "utf8").digest("hex");
      expect(file.sha256).toBe(digest);
      expect(file.fileName).toBe(`assets/jsx-runtime/${file.id}.${digest.slice(0, 10)}.js`);
      expect(built.manifest.files[file.id]).toEqual({ id: file.id, url: `/${file.fileName}`, sha256: digest, bytes: Buffer.byteLength(file.text, "utf8"), provides: file.provides });
    }
  });

  it("emits texts that can sit inside a classic script element", () => {
    for (const file of built.files) {
      expect(file.text, file.id).not.toMatch(/<\/script/i);
      expect(file.text, file.id).not.toContain("<!--");
      expect(file.text.startsWith("__TC_DEFINE__(")).toBe(true);
    }
  });

  it("never bundles code from a network location", () => {
    // Library files carry no CDN, font or source-map URLs to fetch at run time.
    for (const file of built.files) {
      expect(file.text, file.id).not.toMatch(/sourceMappingURL/);
      expect(file.text, file.id).not.toMatch(/@import\s+url\(\s*["']?https?:/i);
    }
  });

  it("bundles only permissively licensed packages and ships a NOTICE that lists them all", () => {
    expect(built.packages.length).toBeGreaterThan(20);
    for (const pkg of built.packages) {
      expect(Object.hasOwn(ALLOWED_LICENCES, pkg.effectiveLicence.split(" AND ")[0]!), `${pkg.name} ${pkg.licence}`).toBe(true);
    }
    const names = built.packages.map((pkg) => pkg.name);
    for (const required of ["react", "react-dom", "sucrase", "lucide-react", "recharts", "d3", "mermaid", "@tailwindcss/browser"]) expect(names).toContain(required);
    // d3-delaunay's dependency is Unlicense; it must not sneak in through the d3 file.
    expect(names).not.toContain("robust-predicates");
    expect(names).not.toContain("delaunator");
    const committed = readFileSync("NOTICE", "utf8");
    expect(committed).toBe(renderNotice(built.packages));
    for (const pkg of built.packages) expect(committed).toContain(`${pkg.name}@${pkg.version}`);
  });

  it("evaluates a licence expression to an allowed alternative or nothing", () => {
    expect(effectiveLicence("MIT")).toBe("MIT");
    expect(effectiveLicence("(MPL-2.0 OR Apache-2.0)")).toBe("Apache-2.0");
    expect(effectiveLicence("MIT AND ISC")).toBe("MIT AND ISC");
    expect(effectiveLicence("MIT AND Unlicense")).toBeUndefined();
    expect(effectiveLicence("GPL-3.0-only")).toBeUndefined();
    expect(effectiveLicence("Unlicense")).toBeUndefined();
  });

  it("registers lazily through the require shim, sharing one React", () => {
    const context = vm.createContext({ console });
    vm.runInContext("var window = globalThis; var document = { documentElement: {} };", context);
    vm.runInContext(JSX_CHILD_PREAMBLE, context);
    for (const id of ["react", "react-dom"]) vm.runInContext(built.files.find((file) => file.id === id)!.text, context);
    // Defining ran no factory yet.
    const has = vm.runInContext("[__TC_HAS__('react'), __TC_HAS__('react/jsx-runtime'), __TC_HAS__('react-dom/client'), __TC_HAS__('lucide-react'), __TC_HAS__('constructor'), __TC_HAS__('__proto__')]", context);
    expect(has).toEqual([true, true, true, false, false, false]);
    expect(vm.runInContext("typeof __TC_REQUIRE__('react').useState", context)).toBe("function");
    expect(vm.runInContext("typeof __TC_REQUIRE__('react/jsx-runtime').jsx", context)).toBe("function");
    expect(vm.runInContext("typeof __TC_REQUIRE__('react-dom/client').createRoot", context)).toBe("function");
    expect(vm.runInContext("__TC_REQUIRE__('react') === __TC_REQUIRE__('react')", context)).toBe(true);
    expect(() => vm.runInContext("__TC_REQUIRE__('constructor')", context)).toThrow(/Cannot find module/);
  });
});
