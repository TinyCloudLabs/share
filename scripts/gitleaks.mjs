#!/usr/bin/env node
// Runs a pinned gitleaks release: downloads it into a private temporary directory,
// verifies its sha256 against the pins below, then runs it with this script's
// arguments and exits with gitleaks' exit code. Any download, checksum or platform
// problem fails the run (exit 2); nothing falls back to an unpinned binary.
//
//   node scripts/gitleaks.mjs git --redact --exit-code 1
//   node scripts/gitleaks.mjs dir dist --redact --exit-code 1
//
// Used by the gitleaks CI job and by scripts/audit-dist.mjs, which the Cloudflare
// Pages build runs. To upgrade: change VERSION and copy the sha256 lines for the
// four archives from the release's gitleaks_<version>_checksums.txt.
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const VERSION = "8.30.1";
const SHA256 = {
  linux_x64: "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb",
  linux_arm64: "e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080",
  darwin_x64: "dfe101a4db2255fc85120ac7f3d25e4342c3c20cf749f2c20a18081af1952709",
  darwin_arm64: "b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5",
};

/** Runs gitleaks with `args`; returns its exit status (2 when it could not run). */
export async function runGitleaks(args) {
  const platform = `${process.platform}_${process.arch}`;
  const sha256 = SHA256[platform];
  if (!sha256) {
    console.error(`gitleaks: no pinned ${VERSION} build for ${platform}`);
    return 2;
  }
  const dir = mkdtempSync(join(tmpdir(), "gitleaks-"));
  try {
    const name = `gitleaks_${VERSION}_${platform}.tar.gz`;
    const url = `https://github.com/gitleaks/gitleaks/releases/download/v${VERSION}/${name}`;
    const response = await fetch(url);
    if (!response.ok) throw new Error(`download ${url}: HTTP ${response.status}`);
    const archive = Buffer.from(await response.arrayBuffer());
    const actual = createHash("sha256").update(archive).digest("hex");
    if (actual !== sha256) throw new Error(`${name}: sha256 ${actual}, expected ${sha256}`);
    writeFileSync(join(dir, name), archive);
    const tar = spawnSync("tar", ["-xzf", join(dir, name), "-C", dir, "gitleaks"], { stdio: "inherit" });
    if (tar.status !== 0) throw new Error(`tar exited ${tar.status ?? tar.signal}`);
    const run = spawnSync(join(dir, "gitleaks"), args, { stdio: "inherit" });
    if (run.error) throw run.error;
    return run.status ?? 2;
  } catch (error) {
    console.error(`gitleaks: ${error instanceof Error ? error.message : error}`);
    return 2;
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  process.exitCode = await runGitleaks(process.argv.slice(2));
}
