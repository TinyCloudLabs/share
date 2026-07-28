import assert from "node:assert/strict";
import test from "node:test";
import { POSTGRES_TLS_HOSTNAME, postgresConnectionUrl, postgresServerCertExtensionFile } from "./postgres-tls-config.mjs";

test("postgresConnectionUrl builds a verify-full URL against the certificate-bound hostname", () => {
  const url = postgresConnectionUrl({ user: "share_email", host: POSTGRES_TLS_HOSTNAME, port: 55123, database: "postgres" });
  assert.equal(url, "postgres://share_email@db.localhost:55123/postgres?sslmode=verify-full");
});

test("postgresConnectionUrl rejects a missing field or a non-numeric port", () => {
  assert.throws(() => postgresConnectionUrl({ user: "", host: POSTGRES_TLS_HOSTNAME, port: 1, database: "postgres" }));
  assert.throws(() => postgresConnectionUrl({ user: "u", host: POSTGRES_TLS_HOSTNAME, port: 0, database: "postgres" }));
  assert.throws(() => postgresConnectionUrl({ user: "u", host: POSTGRES_TLS_HOSTNAME, port: "55123", database: "postgres" }));
});

test("postgresServerCertExtensionFile binds the exact hostname as a server-auth-only SAN", () => {
  const config = postgresServerCertExtensionFile();
  assert.match(config, /subjectAltName=DNS:db\.localhost/);
  assert.match(config, /extendedKeyUsage=serverAuth/);
  assert.match(config, /basicConstraints=CA:FALSE/);
});
