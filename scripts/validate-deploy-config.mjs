#!/usr/bin/env node

import { readFileSync } from "node:fs";

if (process.env.SHARE_TRUST_BUNDLE_ALLOW_TEST === "true") throw new Error("SHARE_TRUST_BUNDLE_ALLOW_TEST is forbidden for deploy configuration");
for (const name of ["SHARE_NODE_TRANSPORT_ORIGIN", "SHARE_CREDENTIALS_TRANSPORT_ORIGIN", "SHARE_REGISTRY_TRANSPORT_ORIGIN", "SHARE_HERMETIC_UPSTREAMS_JSON", "SHARE_HERMETIC_COMPOSITION"]) {
  if (process.env[name] !== undefined) throw new Error(`${name} is forbidden in production deployment configuration`);
}
if (process.env.SHARE_TRUST_BUNDLE !== undefined && process.env.SHARE_TRUST_BUNDLE_FILE !== undefined) throw new Error("configure exactly one Share trust bundle source");
const raw = process.env.SHARE_TRUST_BUNDLE ?? (process.env.SHARE_TRUST_BUNDLE_FILE === undefined ? undefined : readFileSync(process.env.SHARE_TRUST_BUNDLE_FILE, "utf8"));
if (raw === undefined || raw.length === 0) throw new Error("SHARE_TRUST_BUNDLE or SHARE_TRUST_BUNDLE_FILE is required for deploy configuration");
let value;
try { value = JSON.parse(raw); } catch { throw new Error("SHARE_TRUST_BUNDLE must be JSON"); }
const required = ["version", "shareOrigin", "returnOrigin", "registryOrigin", "credentialsOrigin", "nodeOrigin", "nodeAudience", "nodeInvitationKid", "nodeInvitationPublicKey", "nodeKeyVersion", "nodeEnabled", "issuerDid", "issuerVct", "issuerKid", "issuerPublicKey", "issuerKeyVersion", "issuerEnabled"];
if (value?.version !== "tinycloud.share-email-trust-bundle/v1" || Object.keys(value).length !== required.length || required.some((key) => !Object.hasOwn(value, key)) || value.nodeEnabled !== true || value.issuerEnabled !== true || !Number.isSafeInteger(value.nodeKeyVersion) || value.nodeKeyVersion < 1 || !Number.isSafeInteger(value.issuerKeyVersion) || value.issuerKeyVersion < 1) throw new Error("SHARE_TRUST_BUNDLE must be a strict production v1 bundle");
for (const key of ["shareOrigin", "returnOrigin", "registryOrigin", "credentialsOrigin", "nodeOrigin"]) { if (typeof value[key] !== "string" || !/^https:\/\/[^/?#:@]+$/.test(value[key])) throw new Error(`SHARE_TRUST_BUNDLE.${key} must be a canonical HTTPS origin`); }
if (typeof value.nodeAudience !== "string" || value.nodeAudience !== `did:web:${new URL(value.nodeOrigin).hostname}` || typeof value.nodeInvitationKid !== "string" || !value.nodeInvitationKid.startsWith(`${value.nodeAudience}#`) || typeof value.issuerDid !== "string" || typeof value.issuerKid !== "string" || !value.issuerKid.startsWith(`${value.issuerDid}#`)) throw new Error("SHARE_TRUST_BUNDLE trust identity bindings are inconsistent");
if (Object.values(value).some((item) => typeof item === "string" && /(?:node\.example|localhost|127\.0\.0\.1|fixture|placeholder|seed|test)/i.test(item))) throw new Error("production trust bundle contains a placeholder or loopback value");
if (process.env.SHARE_SENDER_ENABLED !== undefined && process.env.SHARE_SENDER_ENABLED !== "true" && process.env.SHARE_SENDER_ENABLED !== "false") throw new Error("SHARE_SENDER_ENABLED must be exactly true or false");
const senderEnabled = process.env.SHARE_SENDER_ENABLED === "true";
if (senderEnabled && (typeof process.env.SHARE_SENDER_PRIVATE_KEY !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(process.env.SHARE_SENDER_PRIVATE_KEY))) throw new Error("SHARE_SENDER_PRIVATE_KEY must be supplied separately by the secret manager");
if (senderEnabled && process.env.SHARE_SENDER_CAPABILITY_JSON !== undefined && process.env.SHARE_SENDER_CAPABILITIES_JSON !== undefined) throw new Error("configure exactly one sender capability source");
if (senderEnabled && typeof process.env.SHARE_SENDER_CAPABILITY_JSON !== "string" && typeof process.env.SHARE_SENDER_CAPABILITIES_JSON !== "string") throw new Error("an authenticated sender capability is required");
if (senderEnabled) {
  let capabilities;
  try {
    capabilities = process.env.SHARE_SENDER_CAPABILITIES_JSON === undefined
      ? [JSON.parse(process.env.SHARE_SENDER_CAPABILITY_JSON)]
      : JSON.parse(process.env.SHARE_SENDER_CAPABILITIES_JSON).map((item) => JSON.parse(item));
  } catch { throw new Error("sender capabilities must be non-empty JSON capability documents"); }
  if (!Array.isArray(capabilities) || capabilities.length === 0 || capabilities.some((item) => typeof item !== "object" || item === null || Array.isArray(item) || typeof item.scope !== "object" || typeof item.source !== "object" || typeof item.policy !== "object")) throw new Error("sender capabilities must be non-empty JSON capability documents");
}
if (process.env.SHARE_AUTH_USERS_JSON !== undefined) {
  try { const users = JSON.parse(process.env.SHARE_AUTH_USERS_JSON); if (!Array.isArray(users) || users.some((user) => typeof user?.userId !== "string" || typeof user?.username !== "string" || typeof user?.passwordHash !== "string" || !user.passwordHash.startsWith("scrypt$"))) throw new Error(); } catch { throw new Error("SHARE_AUTH_USERS_JSON must contain scrypt-authenticated users"); }
}
if (senderEnabled && (typeof process.env.SHARE_BINDING_STORE_PATH !== "string" || !process.env.SHARE_BINDING_STORE_PATH.startsWith("/"))) throw new Error("SHARE_BINDING_STORE_PATH must be an absolute durable production path");
console.log("deploy trust bundle: valid production composition");
