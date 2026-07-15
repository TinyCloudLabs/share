import { cpSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";

const PINNED_COMMIT = "390253aca30628f2ac2be28e64d8e3830da07aaa";
const here = dirname(fileURLToPath(import.meta.url));
const nodeRepoInput = process.env.TINYCLOUD_NODE_DIR ?? process.argv[2];
if (nodeRepoInput === undefined) {
  throw new Error("pass TINYCLOUD_NODE_DIR (or argv[2]) pointing to tinycloud-node");
}
const nodeRepo = resolve(nodeRepoInput);
const sdkManifest = join(nodeRepo, "tinycloud-sdk-wasm/Cargo.toml");
if (!existsSync(sdkManifest) || readFileSync(sdkManifest, "utf8").length === 0) {
  throw new Error("TINYCLOUD_NODE_DIR does not contain tinycloud-sdk-wasm");
}
const actualCommit = execFileSync("git", ["-C", nodeRepo, "rev-parse", "HEAD"], { encoding: "utf8" }).trim();
if (actualCommit !== PINNED_COMMIT) {
  throw new Error(`native fixture requires tinycloud-node ${PINNED_COMMIT}, got ${actualCommit}`);
}

const scratch = mkdtempSync(join(tmpdir(), "tinycloud-share-native-oracle-"));
try {
  writeFileSync(join(scratch, "Cargo.toml"), `[package]
name = "tinycloud-share-native-oracle"
version = "0.0.0"
edition = "2021"

[dependencies]
serde_json = "1"
time = "0.3"
tokio = { version = "1", features = ["fs", "macros", "rt-multi-thread"] }
tinycloud-auth = { path = ${JSON.stringify(join(nodeRepo, "tinycloud-auth"))} }
tinycloud-core = { path = ${JSON.stringify(join(nodeRepo, "tinycloud-core"))} }
`);
  cpSync(join(nodeRepo, "Cargo.lock"), join(scratch, "Cargo.lock"));
  cpSync(join(here, "oracle.rs"), join(scratch, "src/main.rs"));
  const vectorPath = resolve(here, "../vectors/recipient-did-v2.json");
  execFileSync("cargo", ["run", "--quiet", "--", vectorPath], {
    cwd: scratch,
    stdio: "inherit",
  });
} finally {
  rmSync(scratch, { recursive: true, force: true });
}
