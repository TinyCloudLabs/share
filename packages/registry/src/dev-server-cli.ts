/**
 * CLI wrapper around the dev registry server.
 * Run: `npm run -w @tinycloud/share-registry dev-server -- --port 8787`
 * Flags: --port <n> (default 8787), --max-blob-bytes <n>, --sweep-interval-ms <n>
 */
import { serveDevRegistry } from "./dev-server.js";

function intFlag(name: string): number | undefined {
  const index = process.argv.indexOf(`--${name}`);
  if (index === -1) return undefined;
  const raw = process.argv[index + 1];
  const value = raw === undefined ? Number.NaN : Number.parseInt(raw, 10);
  if (!Number.isInteger(value) || value < 0) {
    console.error(`invalid --${name}: ${raw ?? "(missing)"}`);
    process.exit(1);
  }
  return value;
}

const port = intFlag("port") ?? 8787;
const maxBlobBytes = intFlag("max-blob-bytes");
const sweepIntervalMs = intFlag("sweep-interval-ms");

const running = await serveDevRegistry({
  port,
  ...(maxBlobBytes === undefined ? {} : { maxBlobBytes }),
  ...(sweepIntervalMs === undefined ? {} : { sweepIntervalMs }),
});

console.log(`dev share registry listening on ${running.url}`);
console.log(`  upload:  POST ${running.url}/blobs`);
console.log(`  fetch:   GET  ${running.url}/ipfs/<cid>?format=raw`);
console.log(`  max blob: ${running.registry.maxBlobBytes} bytes`);

const shutdown = (): void => {
  void running.close().then(() => process.exit(0));
};
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
