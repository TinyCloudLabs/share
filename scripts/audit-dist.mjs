#!/usr/bin/env node
// Audits a built static site before it ships: `node scripts/audit-dist.mjs <dir>`.
// Chained into `build:deploy` and `build:usercontent`, so the Cloudflare Pages build
// itself fails on a finding and nothing is deployed. It refuses:
//   - source maps (`*.map` files or a `sourceMappingURL` comment);
//   - a file type outside the allowlist below;
//   - text matching a key or token pattern (printed redacted: rule, file, line);
// then runs pinned `gitleaks dir <dir> --redact --config .gitleaks.toml` (scripts/gitleaks.mjs): the repository's
// config, which extends the default rules, so every default rule still scans the built files.
// A missing directory, an empty one or a gitleaks that cannot run also fails.
import { readdirSync, readFileSync, statSync } from "node:fs";
import { basename, extname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { runGitleaks } from "./gitleaks.mjs";

const EXTENSIONS = new Set([
  ".html", ".js", ".css", ".json", ".txt", ".md", ".sql", ".jsx",
  ".svg", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".woff", ".woff2",
]);
const NAMES = new Set(["_headers", "_redirects"]); // Cloudflare Pages control files
const BINARY = new Set([".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".woff", ".woff2"]);

const PATTERNS = [
  ["stripe-live-secret", /\bsk_live_[0-9A-Za-z]{8,}/g],
  ["stripe-live-restricted", /\brk_live_[0-9A-Za-z]{8,}/g],
  ["pem-block", /-----BEGIN [A-Z0-9 ]*-----/g],
  ["hex-32-bytes", /\b0x[0-9a-fA-F]{64}(?![0-9a-fA-F])/g],
  ["slack-token", /\bxox[bp]-[0-9A-Za-z-]{10,}/g],
  ["jwt", /\beyJ[0-9A-Za-z_-]{8,}\.eyJ[0-9A-Za-z_-]{8,}\.[0-9A-Za-z_-]*/g],
  ["aws-access-key", /\bAKIA[0-9A-Z]{16}\b/g],
  ["github-pat", /\bghp_[0-9A-Za-z]{36}\b/g],
  ["github-fine-grained-pat", /\bgithub_pat_[0-9A-Za-z_]{22,}/g],
  ["npm-token", /\bnpm_[0-9A-Za-z]{36}\b/g],
];

// Public constants that match `hex-32-bytes` inside bundled libraries (ethers, viem,
// @noble/curves), by exact value. None is a key. Add one only with its source.
const PUBLIC_HEX = new Set([
  // ethers: zero word, uint256 max, int256 min (as -0x8...) and max
  "0x0000000000000000000000000000000000000000000000000000000000000000",
  "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
  "0x8000000000000000000000000000000000000000000000000000000000000000",
  "0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
  // ethers: checksum of the English BIP-39 wordlist
  "0x3c8acc1e7b08d8e76f9fda015ef48dc8c710a73cb7e0f77b2c18a9b5a7adde60",
  // secp256k1 (SEC 2): n, p, GLV endomorphism beta
  "0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
  "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
  "0x7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee",
  // ed25519 (RFC 8032): p, n, a (= -1 mod p), d, Gx, Gy
  "0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed",
  "0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed",
  "0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffec",
  "0x52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3",
  "0x216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a",
  "0x6666666666666666666666666666666666666666666666666666666666666658",
  // P-256 (FIPS 186-4): p, n, a, b, Gx, Gy
  "0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
  "0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
  "0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
  "0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
  "0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
  "0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
]);

const root = process.argv[2];
if (!root) {
  console.error("Usage: node scripts/audit-dist.mjs <dir>");
  process.exit(2);
}

function* walk(dir) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) yield* walk(path);
    else yield path;
  }
}

const redact = (value) => `${value.slice(0, 4)}…(${value.length} chars)`;
const findings = [];
let files = 0;
for (const path of walk(root)) {
  files += 1;
  const file = relative(root, path);
  const ext = extname(path).toLowerCase();
  if (ext === ".map") {
    findings.push(`${file}: source map`);
    continue;
  }
  if (!EXTENSIONS.has(ext) && !NAMES.has(basename(path))) {
    findings.push(`${file}: file type not in the allowlist`);
    continue;
  }
  if (BINARY.has(ext) || !statSync(path).isFile()) continue;
  const lines = readFileSync(path, "utf8").split("\n");
  lines.forEach((line, index) => {
    if (/[#@]\s*sourceMappingURL=/.test(line)) findings.push(`${file}:${index + 1}: sourceMappingURL`);
    for (const [rule, pattern] of PATTERNS) {
      for (const [match] of line.matchAll(pattern)) {
        if (rule === "hex-32-bytes" && PUBLIC_HEX.has(match.toLowerCase())) continue;
        findings.push(`${file}:${index + 1}: ${rule} ${redact(match)}`);
      }
    }
  });
}

if (files === 0) findings.push(`${root}: no files`);
if (findings.length > 0) {
  console.error(`audit-dist: ${findings.length} finding(s) in ${root}:`);
  for (const finding of findings) console.error(`  ${finding}`);
  process.exit(1);
}
console.log(`audit-dist: ${files} files in ${root}, no source maps, file types and patterns clean`);

// `dir` reads no config from the working directory, so name the repository's. Without it a built bundle is scanned
// with the default rules alone, and the base64 of the inlined web-sdk-wasm trips facebook-page-access-token.
const config = fileURLToPath(new URL("../.gitleaks.toml", import.meta.url));
const status = await runGitleaks(["dir", root, "--redact", "--exit-code", "1", "--no-banner", "--config", config]);
if (status !== 0) {
  console.error(`audit-dist: gitleaks dir ${root} exited ${status}`);
  process.exit(1);
}
