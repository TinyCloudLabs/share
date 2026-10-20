/**
 * Regenerates NOTICE from the JSX runtime build's metafile:
 *   npm run notice:jsx
 * `test/jsx-runtime.test.ts` fails when the committed file is stale, and the
 * build fails when a bundled package is outside the permissive-licence policy.
 */
import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { buildJsxRuntime, renderNotice } from "../src/artifact/jsx-runtime/build.ts";

const { packages } = await buildJsxRuntime();
writeFileSync(fileURLToPath(new URL("../NOTICE", import.meta.url)), renderNotice(packages));
console.log(`NOTICE: ${packages.length} packages`);
