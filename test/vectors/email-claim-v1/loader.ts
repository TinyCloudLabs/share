import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

/** TypeScript consumer surface for the language-neutral fixture bundle. */
export interface FixtureManifest {
  manifestVersion: 1;
  contractVersion: "tinycloud.share-email-claim/v1";
  files: Record<string, string>;
  testOnly: true;
  manifestDigest: string;
}

export interface FixtureBundle {
  manifest: FixtureManifest;
  positive: unknown;
  negative: unknown;
  states: unknown;
  domains: unknown;
  schemas: unknown;
}

const text = new TextEncoder();
const b64 = (bytes: Uint8Array): string => Buffer.from(bytes).toString("base64url");
const sha256 = (bytes: Uint8Array): Uint8Array => new Uint8Array(createHash("sha256").update(bytes).digest());
const digest = (bytes: Uint8Array): string => b64(sha256(bytes));

function jcs(value: unknown): string {
  if (value === null || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "string") {
    for (let i = 0; i < value.length; i++) {
      const unit = value.charCodeAt(i);
      if (unit >= 0xd800 && unit <= 0xdbff) { const next = value.charCodeAt(i + 1); if (!(next >= 0xdc00 && next <= 0xdfff)) throw new TypeError("lone surrogate"); i++; }
      else if (unit >= 0xdc00 && unit <= 0xdfff) throw new TypeError("lone surrogate");
    }
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value) || !Number.isSafeInteger(value)) throw new TypeError("unsafe number");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(jcs).join(",")}]`;
  if (typeof value !== "object" || Object.getPrototypeOf(value) !== Object.prototype) throw new TypeError("non-plain value");
  return `{${Object.keys(value).sort().map((key) => { const child = (value as Record<string, unknown>)[key]; if (child === undefined) throw new TypeError("undefined"); return `${JSON.stringify(key)}:${jcs(child)}`; }).join(",")}}`;
}

const here = dirname(fileURLToPath(import.meta.url));
const readJson = async <T>(path: string): Promise<T> => JSON.parse(await readFile(path, "utf8")) as T;

/** Loads and verifies the manifest and every byte-addressed bundle member. */
export async function loadFixtureBundle(baseDir = here): Promise<FixtureBundle> {
  const manifest = await readJson<FixtureManifest>(resolve(baseDir, "manifest.json"));
  const { manifestDigest: _ignored, ...manifestCore } = manifest;
  if (manifest.manifestDigest !== digest(text.encode(jcs(manifestCore)))) throw new Error("email-claim-v1 manifest digest mismatch");
  const specDir = resolve(baseDir, "../../../specs/email-claim-v1");
  for (const [name, expected] of Object.entries(manifest.files)) {
    const path = name === "README.md" || name === "domains.json" || name === "schemas.json" ? resolve(specDir, name) : resolve(baseDir, name);
    if (digest(await readFile(path)) !== expected) throw new Error(`email-claim-v1 file digest mismatch: ${name}`);
  }
  return {
    manifest,
    positive: await readJson(resolve(baseDir, "positive.json")),
    negative: await readJson(resolve(baseDir, "negative.json")),
    states: await readJson(resolve(baseDir, "states.json")),
    domains: await readJson(resolve(specDir, "domains.json")),
    schemas: await readJson(resolve(specDir, "schemas.json")),
  };
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))) {
  loadFixtureBundle().then(({ manifest }) => console.log(`email-claim-v1 loader: ${manifest.manifestDigest}`)).catch((error: unknown) => {
    console.error(error instanceof Error ? error.message : error);
    process.exitCode = 1;
  });
}
