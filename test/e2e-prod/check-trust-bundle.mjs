/**
 * Static checks on the LIVE production trust bundle.
 *
 * These re-implement, against the deployed `config.json`, the predicates the
 * Web SDK applies to a delivery authorization at
 * `verifyShareDeliveryAuthorization`:
 *
 *   typeof authorization.openCredentialsAudience === "string"
 *   && isCanonicalHttpsOrigin(authorization.openCredentialsAudience)
 *   && authorization.openCredentialsAudience === input.credentialsAudience
 *   && authorization.openCredentialsAudience !== authorization.nodeAudience
 *   && authorization.openCredentialsAudience !== authorization.returnOrigin
 *
 * `input.credentialsAudience` is `config.credentialsOrigin` (composer.ts). So
 * three of the five are decidable from the public config alone. The fourth
 * (`!== returnOrigin`) needs the Node's authorization response, because
 * `returnOrigin` is a field of that response and never reaches the browser
 * config; stage2-addressed.mjs captures it live.
 *
 * Run: node check-trust-bundle.mjs
 */

const SHARE_ORIGIN = process.env.SHARE_ORIGIN ?? "https://share.tinycloud.xyz";
const CONFIG_PATH = "/.well-known/tinycloud-share/config.json";

function isCanonicalHttpsOrigin(value) {
  let url;
  try {
    url = new URL(value);
  } catch {
    return false;
  }
  return url.protocol === "https:" && url.origin === value && url.pathname === "/" && url.search === "" && url.hash === "" && url.username === "" && url.password === "";
}

const checks = [];
function check(name, ok, detail) {
  checks.push({ name, ok, detail });
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${detail === undefined ? "" : ` — ${detail}`}`);
}

const configResponse = await fetch(`${SHARE_ORIGIN}${CONFIG_PATH}`, { cache: "no-store" });
if (!configResponse.ok) throw new Error(`config.json ${configResponse.status}`);
const config = await configResponse.json();
console.log(`--- ${SHARE_ORIGIN}${CONFIG_PATH} ---`);
console.log(JSON.stringify(config, null, 2));
console.log("");

const credentialsAudience = config.credentialsOrigin;

check("credentialsOrigin is a canonical https origin", isCanonicalHttpsOrigin(credentialsAudience), credentialsAudience);
check(
  "openCredentialsAudience source (config.credentialsOrigin) is what the composer passes as credentialsAudience",
  typeof credentialsAudience === "string" && credentialsAudience.length > 0,
  `composer.ts passes credentialsAudience: config.credentialsOrigin = ${credentialsAudience}`,
);
check("credentialsOrigin !== nodeAudience", credentialsAudience !== config.nodeAudience, `${credentialsAudience} vs ${config.nodeAudience}`);
check("credentialsOrigin !== shareOrigin (the value the host bundle uses for returnOrigin)", credentialsAudience !== config.shareOrigin, `${credentialsAudience} vs ${config.shareOrigin}`);
check("nodeAudience matches did:web of nodeOrigin", config.nodeAudience === `did:web:${new URL(config.nodeOrigin).hostname}`, config.nodeAudience);
check("nodeInvitationKid is scoped to nodeAudience", typeof config.nodeInvitationKid === "string" && config.nodeInvitationKid.startsWith(`${config.nodeAudience}#`), config.nodeInvitationKid);
check("nodeInvitationPublicKey is 32 bytes base64url", /^[A-Za-z0-9_-]{43}$/.test(config.nodeInvitationPublicKey ?? ""), config.nodeInvitationPublicKey);
check("issuerPublicKey is 32 bytes base64url", /^[A-Za-z0-9_-]{43}$/.test(config.issuerPublicKey ?? ""), config.issuerPublicKey);
check("nodeEnabled", config.nodeEnabled === true);
check("issuerEnabled", config.issuerEnabled === true);

const nodeInfo = await fetch(`${config.nodeOrigin}/info`, { cache: "no-store" }).then((r) => r.json());
console.log(`\n--- ${config.nodeOrigin}/info ---`);
console.log(JSON.stringify(nodeInfo, null, 2));
check("node advertises the sharing feature", (nodeInfo.features ?? []).includes("sharing"), (nodeInfo.features ?? []).join(","));

const readiness = await fetch("https://api.share.tinycloud.xyz/health/readiness", { cache: "no-store" }).then((r) => r.json());
console.log(`\n--- api.share.tinycloud.xyz/health/readiness ---`);
console.log(JSON.stringify(readiness));

console.log("\nNOT decidable from public data:");
console.log("  openCredentialsAudience !== returnOrigin — returnOrigin is a field of the Node's");
console.log("  delivery-authorization response, not of config.json. stage2-addressed.mjs captures it.");

const failed = checks.filter((entry) => !entry.ok);
if (failed.length > 0) {
  console.error(`\n${failed.length} check(s) failed`);
  process.exit(1);
}
console.log(`\nall ${checks.length} static trust-bundle checks passed`);
