export const CATALOG_SCHEMA: "tinycloud.share.apps-catalog/v1";
export const BUNDLE_URL_PREFIX: "/apps/b/";
export const MANIFEST_PATH: "manifest.json";
export const KNOWLEDGE_DIR: "knowledge";

export interface BundleFile { path: string; sha256: string; size: number }

export interface BundleDescription {
  manifest: { path: string; sha256: string };
  bundle: { root: string; files: BundleFile[]; digest: string };
  knowledge: { root: string; digest: string } | null;
}

export function sha256Hex(bytes: Uint8Array): string;
export function bundlePathProblem(path: unknown): string | null;
export function compareByPath(a: { path: string }, b: { path: string }): number;
export function sortedFiles(files: BundleFile[]): BundleFile[];
export function fileListText(files: BundleFile[]): string;
export function fileListDigest(files: BundleFile[]): string;
export function bundleRootFor(digest: string): string;
export function knowledgeFiles(files: BundleFile[]): BundleFile[];
export function listFiles(dir: string): BundleFile[];
export function describeBundle(dir: string): BundleDescription;
export function verifyCatalog(catalog: unknown, publicDir: string): string[];
