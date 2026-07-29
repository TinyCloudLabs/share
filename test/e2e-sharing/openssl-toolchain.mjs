// TC-340. The harness mints throwaway CA/server TLS material for its own
// Postgres. It used to shell out to bare `openssl`, i.e. to whatever binary
// happened to be first on PATH — which on a developer machine is routinely a
// conda or system build rather than the one the database links against.
//
// That is not a cosmetic difference. OpenSSL 1.1.1's `req -x509` applies the
// config file's `v3_ca` section *and* any `-addext`, so a CA generated with
// `-addext basicConstraints=critical,CA:true` carries basicConstraints twice.
// OpenSSL 3 — which the Homebrew postgres/psql this harness launches links
// against — refuses a certificate with repeated extensions, and the harness
// died several layers away inside migrate.sh with `psql: SSL error: invalid
// certificate`, naming neither the certificate nor the binary that made it.
//
// So: resolve and pin the binary explicitly, require OpenSSL >= 3, and re-read
// the generated material before Postgres ever sees it. Every failure mode here
// names the resolved binary, its version, and the remedy.

/**
 * Candidates are tried in order. Homebrew's `openssl@3` keg is first because
 * it is the exact library the Homebrew `postgresql@16` this harness launches
 * links against. Ambient PATH is deliberately NOT consulted.
 */
export const OPENSSL_CANDIDATE_PATHS = Object.freeze([
  "/opt/homebrew/opt/openssl@3/bin/openssl",
  "/opt/homebrew/bin/openssl",
  "/usr/local/opt/openssl@3/bin/openssl",
  "/usr/local/bin/openssl",
]);

/** Explicit operator override. Still version-checked: a wrong pin must fail loudly, not silently. */
export const OPENSSL_OVERRIDE_ENV = "SHARING_E2E_OPENSSL";

export const MINIMUM_OPENSSL_MAJOR = 3;

const REMEDY = `install Homebrew's openssl@3 (\`brew install openssl@3\`) or pin an OpenSSL ${MINIMUM_OPENSSL_MAJOR}+ binary with ${OPENSSL_OVERRIDE_ENV}=/path/to/openssl`;

/** Parse the first line of `openssl version`. Returns undefined for non-OpenSSL builds (e.g. LibreSSL). */
export function parseOpensslVersion(banner) {
  if (typeof banner !== "string") return undefined;
  const first = banner.trim().split("\n")[0]?.trim() ?? "";
  const match = /^OpenSSL\s+(\d+)\.(\d+)(?:\.(\d+))?/.exec(first);
  if (match === null) return undefined;
  return Object.freeze({ major: Number(match[1]), minor: Number(match[2]), patch: match[3] === undefined ? 0 : Number(match[3]), banner: first });
}

/**
 * Resolve the pinned OpenSSL binary.
 *
 * @param {object} input
 * @param {string|undefined} input.override explicit pin (process.env[OPENSSL_OVERRIDE_ENV])
 * @param {readonly string[]} [input.candidates]
 * @param {(path: string) => string} input.probe runs `<path> version`; throw if absent/not executable
 * @returns {{ path: string, version: { major: number, minor: number, patch: number, banner: string } }}
 */
export function resolveOpensslBinary({ override, candidates = OPENSSL_CANDIDATE_PATHS, probe }) {
  if (typeof probe !== "function") throw new TypeError("resolveOpensslBinary requires a probe function");
  const pinned = typeof override === "string" && override.trim().length > 0 ? override.trim() : undefined;
  const ordered = pinned === undefined ? [...candidates] : [pinned];
  if (ordered.length === 0) throw new Error("resolveOpensslBinary requires at least one candidate path");
  const attempts = [];
  for (const path of ordered) {
    let banner;
    try {
      banner = probe(path);
    } catch (error) {
      attempts.push({ path, reason: `not executable (${error instanceof Error ? error.message : String(error)})`.slice(0, 200) });
      continue;
    }
    const version = parseOpensslVersion(banner);
    if (version === undefined) {
      attempts.push({ path, reason: `not an OpenSSL build: ${String(banner).trim().split("\n")[0] ?? ""}`.slice(0, 200) });
      continue;
    }
    if (version.major < MINIMUM_OPENSSL_MAJOR) {
      attempts.push({ path, reason: `${version.banner} is older than OpenSSL ${MINIMUM_OPENSSL_MAJOR} and emits duplicate X.509 extensions that Postgres rejects` });
      continue;
    }
    return Object.freeze({ path, version });
  }
  const source = pinned === undefined ? "candidate" : `${OPENSSL_OVERRIDE_ENV} pin`;
  throw new Error(`no usable OpenSSL ${MINIMUM_OPENSSL_MAJOR}+ binary: every ${source} was rejected — ${attempts.map((attempt) => `${attempt.path}: ${attempt.reason}`).join("; ")}. The harness never falls back to PATH because the first ambient openssl is frequently older than the one Postgres links against; ${REMEDY}.`);
}

/**
 * Names of X.509 extensions that appear more than once in `openssl x509 -text`
 * output. Non-empty means the generating toolchain produced a certificate that
 * OpenSSL 3 (and therefore Postgres) will reject.
 */
export function duplicateCertificateExtensions(certificateText) {
  if (typeof certificateText !== "string") throw new TypeError("duplicateCertificateExtensions requires openssl x509 -text output");
  const lines = certificateText.split("\n");
  const header = lines.findIndex((line) => /^\s*X509v3 extensions:\s*$/.test(line));
  if (header === -1) return [];
  const headerIndent = lines[header].length - lines[header].trimStart().length;
  const counts = new Map();
  let entryIndent;
  for (let index = header + 1; index < lines.length; index += 1) {
    const line = lines[index];
    if (line.trim().length === 0) continue;
    const indent = line.length - line.trimStart().length;
    if (indent <= headerIndent) break;
    if (entryIndent === undefined) entryIndent = indent;
    if (indent !== entryIndent) continue;
    const name = /^([^:]+):/.exec(line.trim())?.[1]?.trim();
    if (name === undefined || name.length === 0) continue;
    counts.set(name, (counts.get(name) ?? 0) + 1);
  }
  return [...counts.entries()].filter(([, count]) => count > 1).map(([name]) => name).sort();
}

/**
 * Diagnostic for a certificate the pinned toolchain produced but Postgres
 * cannot load. Kept pure so the exact operator-facing wording is unit tested.
 */
export function tlsMaterialDiagnostic({ label, openssl, detail }) {
  if (typeof label !== "string" || label.length === 0) throw new TypeError("tlsMaterialDiagnostic requires a label");
  if (openssl?.path === undefined || openssl?.version?.banner === undefined) throw new TypeError("tlsMaterialDiagnostic requires the resolved openssl");
  return `harness ${label} TLS material generated by the pinned ${openssl.path} (${openssl.version.banner}) is not usable by the local Postgres: ${detail}. Postgres links OpenSSL ${MINIMUM_OPENSSL_MAJOR}, which rejects certificates carrying a repeated X.509 extension — the signature of an OpenSSL 1.1.1 \`req -x509 -addext\`. To pin a different toolchain, ${REMEDY}.`;
}
