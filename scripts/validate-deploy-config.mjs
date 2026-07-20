#!/usr/bin/env node

const raw = process.env.SHARE_TRUST_BUNDLE;
if (raw === undefined || raw.length === 0) throw new Error("SHARE_TRUST_BUNDLE is required for deploy configuration");
let value;
try { value = JSON.parse(raw); } catch { throw new Error("SHARE_TRUST_BUNDLE must be JSON"); }
const required = ["version", "shareOrigin", "returnOrigin", "registryOrigin", "credentialsOrigin", "nodeOrigin", "nodeAudience", "nodeInvitationKid", "nodeInvitationPublicKey", "nodeKeyVersion", "nodeEnabled", "issuerDid", "issuerVct", "issuerKid", "issuerPublicKey", "issuerKeyVersion", "issuerEnabled"];
if (value?.version !== "tinycloud.share-email-trust-bundle/v1" || Object.keys(value).length !== required.length || required.some((key) => !Object.hasOwn(value, key)) || value.nodeEnabled !== true || value.issuerEnabled !== true || !Number.isSafeInteger(value.nodeKeyVersion) || value.nodeKeyVersion < 1 || !Number.isSafeInteger(value.issuerKeyVersion) || value.issuerKeyVersion < 1) throw new Error("SHARE_TRUST_BUNDLE must be a strict production v1 bundle");
if (Object.values(value).some((item) => typeof item === "string" && /(?:node\.example|localhost|127\.0\.0\.1|fixture|placeholder|seed|test)/i.test(item))) throw new Error("production trust bundle contains a placeholder or loopback value");
if (typeof process.env.SHARE_SENDER_PRIVATE_KEY !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(process.env.SHARE_SENDER_PRIVATE_KEY)) throw new Error("SHARE_SENDER_PRIVATE_KEY must be supplied separately by the secret manager");
console.log("deploy trust bundle: valid production composition");
