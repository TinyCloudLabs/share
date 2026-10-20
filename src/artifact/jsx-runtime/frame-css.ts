/**
 * Build/test only (Node): the TinyCloud CSS inlined into every JSX artifact
 * frame, in cascade order. `index.css` is not used because its `@import`s
 * would be network loads inside a frame that refuses all of them.
 */
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";

export function readJsxFrameCss(): string {
  const require = createRequire(import.meta.url);
  return ["tokens.css", "base.css", "patterns.css"]
    .map((file) => readFileSync(require.resolve(`@tinycloud/styles/${file}`), "utf8"))
    .join("\n");
}
