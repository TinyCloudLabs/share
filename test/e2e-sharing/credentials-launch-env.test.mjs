import assert from "node:assert/strict";
import test from "node:test";
import { buildCredentialsLaunchEnv, buildMigrationEnv, databasePoolEnv } from "./credentials-launch-env.mjs";

const baseArgs = {
  tempRoot: "/tmp/example-tempRoot",
  credentialsPort: 4123,
  corsOrigin: "https://share.tinycloud.xyz",
  dstackSocket: "/tmp/example-tempRoot/dstack.sock",
  didWeb: "did:web:issuer.credentials.org",
  trustBundleJson: JSON.stringify({ version: "tinycloud.share-email-trust-bundle/v1" }),
  shareUrl: "https://share.tinycloud.xyz",
  resendApiKey: `re_${"a".repeat(32)}`,
  resendWebhookSecret: "whsec_AAAAAAAAAAAAAAAAAAAAAAAA",
  postgresUrl: "postgres://share_email@db.localhost:55123/postgres?sslmode=verify-full",
  postgresCaCert: "/tmp/example-tempRoot/pg-ca.pem",
  migrationsDir: "/opt/opencredentials/deploy/share-email/migrations",
  readinessFile: "/tmp/example-tempRoot/readiness.json",
};

test("buildMigrationEnv shares the exact durable-postgres pool bounds readiness-check.sh requires", () => {
  const env = buildMigrationEnv({ postgresUrl: baseArgs.postgresUrl, postgresCaCert: baseArgs.postgresCaCert, migrationsDir: baseArgs.migrationsDir, readinessFile: baseArgs.readinessFile });
  assert.deepEqual({ DATABASE_POOL_MIN: env.DATABASE_POOL_MIN, DATABASE_POOL_MAX: env.DATABASE_POOL_MAX }, { DATABASE_POOL_MIN: databasePoolEnv().DATABASE_POOL_MIN, DATABASE_POOL_MAX: databasePoolEnv().DATABASE_POOL_MAX });
  assert.equal(env.DATABASE_URL, baseArgs.postgresUrl);
  assert.equal(env.DATABASE_SSL_ROOT_CERT, baseArgs.postgresCaCert);
  assert.equal(env.STORAGE_READINESS_MAX_AGE_SECONDS, "30");
});

test("buildMigrationEnv rejects a missing required field", () => {
  assert.throws(() => buildMigrationEnv({ postgresUrl: "", postgresCaCert: baseArgs.postgresCaCert, migrationsDir: baseArgs.migrationsDir, readinessFile: baseArgs.readinessFile }));
});

test("buildCredentialsLaunchEnv wires KEYS_TYPE=dstack, the simulator socket, and the identical migration pool contract", () => {
  const env = buildCredentialsLaunchEnv(baseArgs);
  assert.equal(env.KEYS_TYPE, "dstack");
  assert.equal(env.DSTACK_SIMULATOR_ENDPOINT, baseArgs.dstackSocket);
  assert.equal(env.BIND_ADDR, `127.0.0.1:${baseArgs.credentialsPort}`);
  assert.equal(env.SHARE_EMAIL_CAPABILITY, "true");
  assert.equal(env.SHARE_EMAIL_TRUST_BUNDLE_JSON, baseArgs.trustBundleJson);
  assert.equal(env.RESEND_API_KEY, baseArgs.resendApiKey);
  assert.equal(env.RESEND_WEBHOOK_SECRET, baseArgs.resendWebhookSecret);
  assert.equal(env.DATABASE_URL, baseArgs.postgresUrl);
  assert.equal(env.DATABASE_POOL_MAX, "8");
  assert.equal(env.SHARE_EMAIL_KEY_DERIVATION_VERSION, "1");
  assert.equal(env.TMPDIR, baseArgs.tempRoot);
});

test("buildCredentialsLaunchEnv never selects the fixture/local-key composition", () => {
  const env = buildCredentialsLaunchEnv(baseArgs);
  assert.equal("OPENCREDENTIALS_SK" in env, false);
  assert.equal("EMAIL_CLAIM_FIXTURE_DATABASE_URL" in env, false);
  assert.equal("SHARE_HERMETIC_COMPOSITION" in env, false);
});

test("buildCredentialsLaunchEnv rejects a non-positive-integer port", () => {
  assert.throws(() => buildCredentialsLaunchEnv({ ...baseArgs, credentialsPort: 0 }));
  assert.throws(() => buildCredentialsLaunchEnv({ ...baseArgs, credentialsPort: "4123" }));
});
