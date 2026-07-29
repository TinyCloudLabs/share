import assert from "node:assert/strict";
import test from "node:test";
import {
  MINIMUM_OPENSSL_MAJOR,
  OPENSSL_CANDIDATE_PATHS,
  OPENSSL_OVERRIDE_ENV,
  duplicateCertificateExtensions,
  parseOpensslVersion,
  resolveOpensslBinary,
  tlsMaterialDiagnostic,
} from "./openssl-toolchain.mjs";

const OPENSSL_3 = "OpenSSL 3.6.3 9 Jun 2026 (Library: OpenSSL 3.6.3 9 Jun 2026)\n";
const OPENSSL_1 = "OpenSSL 1.1.1t  7 Feb 2023\n";
const LIBRESSL = "LibreSSL 3.3.6\n";

test("parseOpensslVersion reads an OpenSSL banner and rejects a LibreSSL one", () => {
  assert.deepEqual({ ...parseOpensslVersion(OPENSSL_3) }, { major: 3, minor: 6, patch: 3, banner: "OpenSSL 3.6.3 9 Jun 2026 (Library: OpenSSL 3.6.3 9 Jun 2026)" });
  assert.equal(parseOpensslVersion(OPENSSL_1).major, 1);
  assert.equal(parseOpensslVersion(LIBRESSL), undefined);
  assert.equal(parseOpensslVersion(undefined), undefined);
});

test("resolveOpensslBinary pins the first candidate that reports OpenSSL 3 and never consults PATH", () => {
  const probed = [];
  const resolved = resolveOpensslBinary({
    override: undefined,
    probe: (path) => {
      probed.push(path);
      if (path === OPENSSL_CANDIDATE_PATHS[0]) throw new Error("ENOENT");
      return OPENSSL_3;
    },
  });
  assert.equal(resolved.path, OPENSSL_CANDIDATE_PATHS[1]);
  assert.equal(resolved.version.major, MINIMUM_OPENSSL_MAJOR);
  assert.deepEqual(probed, [OPENSSL_CANDIDATE_PATHS[0], OPENSSL_CANDIDATE_PATHS[1]]);
  assert.equal(probed.includes("openssl"), false, "bare `openssl` would resolve through ambient PATH");
});

test("resolveOpensslBinary skips an OpenSSL 1.1.1 or LibreSSL candidate rather than accepting it", () => {
  const resolved = resolveOpensslBinary({
    override: undefined,
    candidates: ["/first/openssl", "/second/openssl", "/third/openssl"],
    probe: (path) => (path === "/first/openssl" ? OPENSSL_1 : path === "/second/openssl" ? LIBRESSL : OPENSSL_3),
  });
  assert.equal(resolved.path, "/third/openssl");
});

test("resolveOpensslBinary honours an explicit pin and tries nothing else", () => {
  const probed = [];
  const resolved = resolveOpensslBinary({ override: "  /pinned/openssl  ", probe: (path) => { probed.push(path); return OPENSSL_3; } });
  assert.equal(resolved.path, "/pinned/openssl");
  assert.deepEqual(probed, ["/pinned/openssl"]);
});

test("resolveOpensslBinary fails with a diagnostic naming every rejected candidate and the remedy", () => {
  assert.throws(
    () => resolveOpensslBinary({ override: undefined, candidates: ["/a/openssl", "/b/openssl"], probe: (path) => (path === "/a/openssl" ? OPENSSL_1 : LIBRESSL) }),
    (error) => {
      assert.match(error.message, /\/a\/openssl: OpenSSL 1\.1\.1t/);
      assert.match(error.message, /\/b\/openssl: not an OpenSSL build: LibreSSL 3\.3\.6/);
      assert.match(error.message, /duplicate X\.509 extensions that Postgres rejects/);
      assert.match(error.message, new RegExp(OPENSSL_OVERRIDE_ENV));
      assert.match(error.message, /never falls back to PATH/);
      return true;
    },
  );
});

test("resolveOpensslBinary reports a bad explicit pin as a pin failure", () => {
  assert.throws(
    () => resolveOpensslBinary({ override: "/pinned/openssl", probe: () => OPENSSL_1 }),
    new RegExp(`every ${OPENSSL_OVERRIDE_ENV} pin was rejected`),
  );
});

const OPENSSL_3_CA_TEXT = `Certificate:
    Data:
        Version: 3 (0x2)
        X509v3 extensions:
            X509v3 Subject Key Identifier:
                C9:64:33:03:A9:97:E8:F7
            X509v3 Authority Key Identifier:
                C9:64:33:03:A9:97:E8:F7
            X509v3 Basic Constraints: critical
                CA:TRUE
    Signature Algorithm: sha256WithRSAEncryption
`;

// Verbatim shape of what OpenSSL 1.1.1t emits for
// \`req -x509 ... -addext basicConstraints=critical,CA:true\`.
const OPENSSL_1_CA_TEXT = OPENSSL_3_CA_TEXT.replace(
  "    Signature Algorithm: sha256WithRSAEncryption",
  "            X509v3 Basic Constraints: critical\n                CA:TRUE\n    Signature Algorithm: sha256WithRSAEncryption",
);

test("duplicateCertificateExtensions is empty for an OpenSSL 3 CA and names the repeat for an OpenSSL 1.1.1 one", () => {
  assert.deepEqual(duplicateCertificateExtensions(OPENSSL_3_CA_TEXT), []);
  assert.deepEqual(duplicateCertificateExtensions(OPENSSL_1_CA_TEXT), ["X509v3 Basic Constraints"]);
});

test("duplicateCertificateExtensions never mistakes an extension value line for a second extension", () => {
  const text = `Certificate:
        X509v3 extensions:
            X509v3 Subject Alternative Name:
                DNS:db.localhost
            X509v3 Extended Key Usage:
                TLS Web Server Authentication
            X509v3 Basic Constraints:
                CA:FALSE
    Signature Algorithm: sha256WithRSAEncryption
`;
  assert.deepEqual(duplicateCertificateExtensions(text), []);
});

test("duplicateCertificateExtensions tolerates a certificate with no extension block", () => {
  assert.deepEqual(duplicateCertificateExtensions("Certificate:\n    Data:\n        Version: 1 (0x0)\n"), []);
  assert.throws(() => duplicateCertificateExtensions(undefined));
});

test("tlsMaterialDiagnostic names the certificate, the pinned binary, its version, and the remedy", () => {
  const message = tlsMaterialDiagnostic({
    label: "certificate authority",
    openssl: { path: "/opt/homebrew/opt/openssl@3/bin/openssl", version: { banner: "OpenSSL 3.6.3 9 Jun 2026" } },
    detail: "it repeats X.509 extension(s) X509v3 Basic Constraints",
  });
  assert.match(message, /harness certificate authority TLS material/);
  assert.match(message, /\/opt\/homebrew\/opt\/openssl@3\/bin\/openssl \(OpenSSL 3\.6\.3 9 Jun 2026\)/);
  assert.match(message, /repeats X\.509 extension\(s\) X509v3 Basic Constraints/);
  assert.match(message, new RegExp(OPENSSL_OVERRIDE_ENV));
  assert.throws(() => tlsMaterialDiagnostic({ label: "", openssl: {}, detail: "x" }));
});
