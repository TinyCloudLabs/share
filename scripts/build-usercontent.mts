/**
 * npm run build:usercontent
 *
 * Writes dist-usercontent/ for the user-content Pages project. The viewer
 * origin allowed to frame the documents and to fetch the library files is
 * `USER_CONTENT_VIEWER_ORIGIN` (default https://share.tinycloud.xyz).
 */
import { fileURLToPath } from "node:url";

import { DEFAULT_VIEWER_ORIGIN } from "../src/artifact/user-content/headers.ts";
import { buildUserContent } from "../src/artifact/user-content/build.ts";
import { parseUserContentOrigin } from "../src/viewer/user-content-origin.ts";

const viewerOrigin = parseUserContentOrigin(process.env["USER_CONTENT_VIEWER_ORIGIN"] || DEFAULT_VIEWER_ORIGIN);
const outDir = fileURLToPath(new URL("../dist-usercontent", import.meta.url));
const { files } = await buildUserContent({ outDir, viewerOrigin });
console.log(`dist-usercontent: ${files.length} files, frame-ancestors/CORS ${viewerOrigin}`);
