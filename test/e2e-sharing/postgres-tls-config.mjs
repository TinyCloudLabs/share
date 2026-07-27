// deploy/share-email/validate-database-url.sh rejects "localhost" and any
// bare IP host, so the harness-owned CA/server certificate must bind a
// non-"localhost" hostname under the *.localhost TLD, which every
// production-supported OS resolves to the loopback interface without any
// /etc/hosts edit.
export const POSTGRES_TLS_HOSTNAME = "db.localhost";

export function postgresConnectionUrl({ user, host, port, database }) {
  for (const [name, value] of Object.entries({ user, host, database })) {
    if (typeof value !== "string" || value.length === 0) throw new Error(`postgresConnectionUrl requires ${name}`);
  }
  if (!Number.isInteger(port) || port <= 0) throw new Error("postgresConnectionUrl requires a positive integer port");
  return `postgres://${user}@${host}:${port}/${database}?sslmode=verify-full`;
}

export function postgresServerCertExtensionFile(hostname = POSTGRES_TLS_HOSTNAME) {
  if (typeof hostname !== "string" || hostname.length === 0) throw new Error("postgresServerCertExtensionFile requires a hostname");
  return `subjectAltName=DNS:${hostname}\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\n`;
}
