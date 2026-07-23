/**
 * `tinycloud-share` — bearer-share CLI (stage 4, node-only).
 *
 *   tinycloud-share create <file> [--expires <duration>] [--registry <url>]
 *                                 [--sender-name <name>] [--origin <url>]
 *                                 [--space <id>] [--viewer-origin <url>]
 *
 * Everything cryptographic lives in ./create.ts (shared with the e2e suite);
 * this file is argv parsing + file IO + printing only.
 */
import { readFile } from "node:fs/promises";
import { basename, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { parseArgs } from "node:util";

import { createBearerShare } from "./create.js";
import { parseDuration } from "./duration.js";

const DEFAULT_REGISTRY_URL = "http://127.0.0.1:8787";

export const USAGE = `Usage: tinycloud-share create <file> [options]

Create a BEARER share of a single markdown file: anyone holding the printed
link can read it — the link is the authority. The file content and the share
envelope are sealed (AES-256-GCM) and uploaded to the registry with a
required retention expiry; the decryption key rides only in the URL fragment.

Options:
  --expires <duration>     Share lifetime: <n>s|m|h|d (default 30d)
  --registry <url>         Registry base URL (default ${DEFAULT_REGISTRY_URL})
  --sender-name <name>     Display name shown by the viewer (UNVERIFIED)
  --origin <url>           Target node origin recorded in the envelope
                           (bearer-slice placeholder; default viewer origin)
  --space <id>             Space id in the signed target (default "bearer")
  --viewer-origin <url>    Origin the printed link uses
                           (default https://share.tinycloud.xyz)
`;

export async function main(argv: readonly string[]): Promise<number> {
  let parsed: ReturnType<typeof parseArgs>;
  try {
    parsed = parseArgs({
      args: [...argv],
      allowPositionals: true,
      options: {
        expires: { type: "string" },
        registry: { type: "string" },
        "sender-name": { type: "string" },
        origin: { type: "string" },
        space: { type: "string" },
        "viewer-origin": { type: "string" },
        help: { type: "boolean", short: "h" },
      },
    });
  } catch (error) {
    process.stderr.write(`${message(error)}\n\n${USAGE}`);
    return 1;
  }
  if (parsed.values.help === true) {
    process.stdout.write(USAGE);
    return 0;
  }
  const [command, filePath] = parsed.positionals;
  if (command !== "create" || filePath === undefined) {
    process.stderr.write(USAGE);
    return 1;
  }

  try {
    const expiresMs = parseDuration(
      typeof parsed.values.expires === "string" ? parsed.values.expires : "30d",
    );
    const absolutePath = resolve(filePath);
    const content = new Uint8Array(await readFile(absolutePath));
    const result = await createBearerShare({
      content,
      filename: basename(absolutePath),
      registryBaseUrl:
        typeof parsed.values.registry === "string"
          ? parsed.values.registry
          : DEFAULT_REGISTRY_URL,
      expiresAt: new Date(Date.now() + expiresMs),
      ...(typeof parsed.values["sender-name"] === "string"
        ? { senderName: parsed.values["sender-name"] }
        : {}),
      ...(typeof parsed.values.origin === "string"
        ? { origin: parsed.values.origin }
        : {}),
      ...(typeof parsed.values.space === "string"
        ? { spaceId: parsed.values.space }
        : {}),
      ...(typeof parsed.values["viewer-origin"] === "string"
        ? { viewerOrigin: parsed.values["viewer-origin"] }
        : {}),
    });
    process.stdout.write(
      [
        "Bearer share created. ANYONE with this link can read the file:",
        "",
        `  ${result.url}`,
        "",
        `  envelope CID:      ${result.envelopeCid}`,
        `  content CID:       ${result.contentCid}`,
        `  expires:           ${result.expiry}`,
        `  registry retains:  until ${result.registryDeleteAfter}`,
        "",
      ].join("\n"),
    );
    return 0;
  } catch (error) {
    process.stderr.write(`tinycloud-share: ${message(error)}\n`);
    return 1;
  }
}

function message(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

// Run when executed directly (tsx src/cli.ts / the bin shim calls main itself).
if (
  process.argv[1] !== undefined &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  process.exitCode = await main(process.argv.slice(2));
}
