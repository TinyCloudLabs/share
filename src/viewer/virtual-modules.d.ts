// Ambient module: a relative `import type` is not allowed inside `declare module`.
declare module "virtual:tc-jsx-manifest" {
  const manifest: import("../artifact/jsx-runtime/files.js").JsxManifest;
  export default manifest;
}
