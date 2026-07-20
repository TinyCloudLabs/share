#!/usr/bin/env node

const raw = process.env.SHARE_TRUST_BUNDLE;
if (raw === undefined || raw.length === 0) throw new Error("SHARE_TRUST_BUNDLE is required for deploy configuration");
let value;
try { value = JSON.parse(raw); } catch { throw new Error("SHARE_TRUST_BUNDLE must be JSON"); }
if (value?.version !== 1 || value?.environment !== "production" || typeof value.public !== "object" || typeof value.sender !== "object") throw new Error("SHARE_TRUST_BUNDLE must be a production v1 bundle");
if (Object.values(value.public).some((item) => typeof item === "string" && /(?:node\.example|localhost|127\.0\.0\.1|fixture|placeholder|seed|test)/i.test(item))) throw new Error("production trust bundle contains a placeholder or loopback value");
if (typeof value.sender.senderPrivateKey !== "string" || typeof value.sender.senderPublicKey !== "string") throw new Error("production sender key material is incomplete");
console.log("deploy trust bundle: valid production composition");
