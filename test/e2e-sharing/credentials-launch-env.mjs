// Pool/timeout bounds required verbatim by the committed
// scripts/oi-share-email/readiness-check.sh (durable-postgres mode expects
// exactly pool_min=2/pool_max=8) and by PostgresProductionConfig::from_env().
export function databasePoolEnv() {
  return {
    DATABASE_POOL_MIN: "2",
    DATABASE_POOL_MAX: "8",
    DATABASE_CONNECT_TIMEOUT_MS: "5000",
    DATABASE_RECYCLE_TIMEOUT_MS: "5000",
    DATABASE_ACQUIRE_TIMEOUT_MS: "500",
    DATABASE_STATEMENT_TIMEOUT_MS: "2000",
    DATABASE_IDLE_TRANSACTION_TIMEOUT_MS: "1000",
  };
}

function requireString(values, name) {
  const value = values[name];
  if (typeof value !== "string" || value.length === 0) throw new Error(`${name} is required`);
  return value;
}

function requireLoopbackDeliveryEndpoint(value) {
  let endpoint;
  try { endpoint = new URL(value); } catch { throw new Error("resendEndpoint must be an explicit loopback URL"); }
  const loopback = endpoint.hostname === "127.0.0.1" || endpoint.hostname === "localhost" || endpoint.hostname === "[::1]";
  if (endpoint.protocol !== "http:" || !loopback || endpoint.port.length === 0 || endpoint.username.length > 0 || endpoint.password.length > 0) {
    throw new Error("resendEndpoint must be an explicit loopback URL");
  }
}

// Shared by the migrate.sh and readiness-check.sh invocations, and by the
// witness process itself: all three must observe the identical durable-
// postgres pool/timeout/migrations/freshness-file contract.
export function buildMigrationEnv({ postgresUrl, postgresCaCert, migrationsDir, readinessFile, readinessMaxAgeSeconds = 30 }) {
  const values = { postgresUrl, postgresCaCert, migrationsDir, readinessFile };
  for (const name of Object.keys(values)) requireString(values, name);
  return {
    ...databasePoolEnv(),
    DATABASE_URL: postgresUrl,
    DATABASE_SSL_ROOT_CERT: postgresCaCert,
    DATABASE_MIGRATIONS_DIR: migrationsDir,
    STORAGE_READINESS_FILE: readinessFile,
    STORAGE_READINESS_MAX_AGE_SECONDS: String(readinessMaxAgeSeconds),
  };
}

export function buildCredentialsLaunchEnv({
  tempRoot, credentialsPort, corsOrigin, dstackSocket, didWeb, trustBundleJson, shareUrl,
  resendApiKey, resendWebhookSecret, resendEndpoint, postgresUrl, postgresCaCert, migrationsDir, readinessFile,
  readinessMaxAgeSeconds = 30, keyDerivationVersion = 1,
}) {
  const values = { tempRoot, corsOrigin, dstackSocket, didWeb, trustBundleJson, shareUrl, resendApiKey, resendWebhookSecret, resendEndpoint };
  for (const name of Object.keys(values)) requireString(values, name);
  requireLoopbackDeliveryEndpoint(resendEndpoint);
  if (!Number.isInteger(credentialsPort) || credentialsPort <= 0) throw new Error("credentialsPort must be a positive integer");
  return {
    TMPDIR: tempRoot,
    KEYS_TYPE: "dstack",
    DSTACK_SIMULATOR_ENDPOINT: dstackSocket,
    DID_WEB: didWeb,
    BIND_ADDR: `127.0.0.1:${credentialsPort}`,
    CORS_ALLOWED_ORIGINS: corsOrigin,
    SHARE_EMAIL_CAPABILITY: "true",
    SHARE_EMAIL_TRUST_BUNDLE_JSON: trustBundleJson,
    SHARE_EMAIL_SHARE_URL: shareUrl,
    RESEND_API_KEY: resendApiKey,
    RESEND_WEBHOOK_SECRET: resendWebhookSecret,
    SHARE_EMAIL_RESEND_ENDPOINT: resendEndpoint,
    SHARE_EMAIL_KEY_DERIVATION_VERSION: String(keyDerivationVersion),
    ...buildMigrationEnv({ postgresUrl, postgresCaCert, migrationsDir, readinessFile, readinessMaxAgeSeconds }),
  };
}
