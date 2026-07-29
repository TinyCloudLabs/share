#!/usr/bin/env node

import { readFileSync } from "node:fs";
import { isAbsolute, relative, resolve } from "node:path";

const immutableImage = /^[a-z0-9](?:[a-z0-9./_-]*[a-z0-9])?@sha256:[0-9a-f]{64}$/;
const commit = /^[0-9a-f]{40}$/;
const digest = /^sha256:[0-9a-f]{64}$/;
if (typeof process.env.SHARE_API_IMAGE !== "string" || !immutableImage.test(process.env.SHARE_API_IMAGE)) throw new Error("SHARE_API_IMAGE must be an immutable registry digest reference");
if (process.env.SHARE_TRUST_BUNDLE_ALLOW_TEST === "true") throw new Error("SHARE_TRUST_BUNDLE_ALLOW_TEST is forbidden for deploy configuration");
for (const name of ["SHARE_NODE_TRANSPORT_ORIGIN", "SHARE_CREDENTIALS_TRANSPORT_ORIGIN", "SHARE_REGISTRY_TRANSPORT_ORIGIN", "SHARE_HERMETIC_UPSTREAMS_JSON", "SHARE_HERMETIC_COMPOSITION", "SHARE_HERMETIC_OPENKEY_ORIGIN", "SHARE_HERMETIC_WALLET_ORIGIN", "SHARE_HERMETIC_BROWSER_ORIGIN", "SHARE_HERMETIC_REGISTRY_ORIGIN"]) {
  if (process.env[name] !== undefined) throw new Error(`${name} is forbidden in production deployment configuration`);
}
if (process.env.SHARE_TRUST_BUNDLE !== undefined && process.env.SHARE_TRUST_BUNDLE_FILE !== undefined) throw new Error("configure exactly one Share trust bundle source");
const raw = process.env.SHARE_TRUST_BUNDLE ?? (process.env.SHARE_TRUST_BUNDLE_FILE === undefined ? undefined : readFileSync(process.env.SHARE_TRUST_BUNDLE_FILE, "utf8"));
if (raw === undefined || raw.length === 0) throw new Error("SHARE_TRUST_BUNDLE or SHARE_TRUST_BUNDLE_FILE is required for deploy configuration");
let value;
try { value = JSON.parse(raw); } catch { throw new Error("SHARE_TRUST_BUNDLE must be JSON"); }
const required = ["version", "shareOrigin", "returnOrigin", "registryOrigin", "credentialsOrigin", "nodeOrigin", "nodeAudience", "nodeInvitationKid", "nodeInvitationPublicKey", "nodeKeyVersion", "nodeEnabled", "issuerDid", "issuerVct", "issuerKid", "issuerPublicKey", "issuerKeyVersion", "issuerEnabled"];
if (value?.version !== "tinycloud.share-email-trust-bundle/v1" || Object.keys(value).length !== required.length || required.some((key) => !Object.hasOwn(value, key)) || typeof value.nodeEnabled !== "boolean" || value.issuerEnabled !== true || !Number.isSafeInteger(value.nodeKeyVersion) || value.nodeKeyVersion < 1 || !Number.isSafeInteger(value.issuerKeyVersion) || value.issuerKeyVersion < 1) throw new Error("SHARE_TRUST_BUNDLE must be a strict production v1 bundle");
for (const key of ["shareOrigin", "returnOrigin", "registryOrigin", "credentialsOrigin", "nodeOrigin"]) { if (typeof value[key] !== "string" || !/^https:\/\/[^/?#:@]+$/.test(value[key])) throw new Error(`SHARE_TRUST_BUNDLE.${key} must be a canonical HTTPS origin`); }
if (typeof value.nodeAudience !== "string" || value.nodeAudience !== `did:web:${new URL(value.nodeOrigin).hostname}` || typeof value.nodeInvitationKid !== "string" || !value.nodeInvitationKid.startsWith(`${value.nodeAudience}#`) || typeof value.issuerDid !== "string" || typeof value.issuerKid !== "string" || !value.issuerKid.startsWith(`${value.issuerDid}#`)) throw new Error("SHARE_TRUST_BUNDLE trust identity bindings are inconsistent");
if (Object.values(value).some((item) => typeof item === "string" && /(?:node\.example|localhost|127\.0\.0\.1|fixture|placeholder|seed|test)/i.test(item))) throw new Error("production trust bundle contains a placeholder or loopback value");
if (process.env.SHARE_SENDER_ENABLED !== undefined && process.env.SHARE_SENDER_ENABLED !== "true" && process.env.SHARE_SENDER_ENABLED !== "false") throw new Error("SHARE_SENDER_ENABLED must be exactly true or false");
const senderEnabled = process.env.SHARE_SENDER_ENABLED === "true";
if (senderEnabled && !value.nodeEnabled) throw new Error("SHARE_SENDER_ENABLED=true requires an enabled trusted node");
if (process.env.SHARE_SENDER_PRIVATE_KEY !== undefined || process.env.SHARE_SENDER_CAPABILITY_JSON !== undefined || process.env.SHARE_SENDER_CAPABILITIES_JSON !== undefined) throw new Error("static sender authority variables are forbidden; authenticate through OpenKey");
if (process.env.SHARE_AUTH_USERS_JSON !== undefined) {
  try { const users = JSON.parse(process.env.SHARE_AUTH_USERS_JSON); if (!Array.isArray(users) || users.some((user) => typeof user?.userId !== "string" || typeof user?.username !== "string" || typeof user?.passwordHash !== "string" || !user.passwordHash.startsWith("scrypt$"))) throw new Error(); } catch { throw new Error("SHARE_AUTH_USERS_JSON must contain scrypt-authenticated users"); }
}
const provenanceRaw = process.env.SHARE_RELEASE_PROVENANCE;
if (typeof provenanceRaw !== "string" || provenanceRaw.length === 0) throw new Error("SHARE_RELEASE_PROVENANCE is required for deploy configuration");
let provenance;
try { provenance = JSON.parse(provenanceRaw); } catch { throw new Error("SHARE_RELEASE_PROVENANCE must be JSON"); }
const provenanceKeys = ["releaseId", "shareCommit", "nodeCommit", "openCredentialsCommit", "sdkCommit", "shareApiImage", "configurationDigest", "migrationVersion", "rollbackImage", "rollbackReleaseId"];
if (typeof provenance !== "object" || provenance === null || Array.isArray(provenance) || Object.keys(provenance).length !== provenanceKeys.length || provenanceKeys.some((key) => !Object.hasOwn(provenance, key)) || typeof provenance.releaseId !== "string" || !/^[A-Za-z0-9._-]{1,128}$/.test(provenance.releaseId) || !commit.test(provenance.shareCommit) || !commit.test(provenance.nodeCommit) || !commit.test(provenance.openCredentialsCommit) || !commit.test(provenance.sdkCommit) || provenance.shareApiImage !== process.env.SHARE_API_IMAGE || !digest.test(provenance.configurationDigest) || typeof provenance.migrationVersion !== "string" || !/^[A-Za-z0-9._:-]{1,128}$/.test(provenance.migrationVersion) || !immutableImage.test(provenance.rollbackImage) || typeof provenance.rollbackReleaseId !== "string" || !/^[A-Za-z0-9._-]{1,128}$/.test(provenance.rollbackReleaseId)) throw new Error("SHARE_RELEASE_PROVENANCE must bind reviewed commits, image, configuration, migration, and rollback target");
const bindingStorePath = process.env.SHARE_BINDING_STORE_PATH ?? "/var/lib/tinycloud/share/bindings.ndjson";
if (process.env.SHARE_BINDING_STORE_ROOT !== undefined && process.env.SHARE_BINDING_STORE_ROOT !== "/var/lib/tinycloud/share") throw new Error("SHARE_BINDING_STORE_ROOT is fixed to the named Share volume");
const senderRootKeyPath = process.env.SHARE_SENDER_ROOT_KEY_PATH ?? "/var/lib/tinycloud/share/sender-root.key";
// The sender root seed is host-created key material inside the persistent
// volume, never a supplied secret; it must not collide with the journal.
if (senderEnabled) {
  const seedRemainder = relative(resolve("/var/lib/tinycloud/share"), resolve(senderRootKeyPath));
  if (!isAbsolute(senderRootKeyPath) || senderRootKeyPath.endsWith("/") || senderRootKeyPath.split("/").slice(1).some((segment) => segment === "" || segment === "." || segment === "..") || seedRemainder === "" || seedRemainder.startsWith("..") || isAbsolute(seedRemainder)) {
    throw new Error("SHARE_SENDER_ROOT_KEY_PATH must be a normalized descendant of /var/lib/tinycloud/share");
  }
  // The binding store also owns `<path>.lock`, whose stale-lock reaper would
  // otherwise remove the seed and silently rotate every wallet identity, and
  // the registry upload key is a separate secret with its own lifecycle.
  for (const other of [bindingStorePath, process.env.SHARE_REGISTRY_UPLOAD_KEY_PATH ?? "/var/lib/tinycloud/share/registry-upload.key"]) {
    if (resolve(senderRootKeyPath) === resolve(other) || resolve(senderRootKeyPath) === `${resolve(other)}.lock`) throw new Error("SHARE_SENDER_ROOT_KEY_PATH must not collide with other Share key or journal material");
  }
}
if (senderEnabled) {
  const root = "/var/lib/tinycloud/share";
  const remainder = relative(resolve(root), resolve(bindingStorePath));
  if (!isAbsolute(bindingStorePath) || bindingStorePath.endsWith("/") || bindingStorePath.includes("\u0000") || bindingStorePath.split("/").slice(1).some((segment) => segment === "" || segment === "." || segment === "..") || remainder === "" || remainder.startsWith("..") || isAbsolute(remainder)) {
    throw new Error("SHARE_BINDING_STORE_PATH must be a normalized descendant of /var/lib/tinycloud/share");
  }
}
console.log("deploy trust bundle: valid production composition");
