import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

/** TypeScript consumer surface for the language-neutral fixture bundle. */
export interface FixtureManifest {
  manifestVersion: 1;
  contractVersion: "tinycloud.share-email-claim/v1";
  files: Record<string, string>;
  testOnly: true;
  manifestDigest: string;
}

export interface FixtureBundle {
  manifest: FixtureManifest;
  positive: unknown;
  negative: unknown;
  states: unknown;
  domains: unknown;
  schemas: unknown;
}

const text = new TextEncoder();
const b64 = (bytes: Uint8Array): string => Buffer.from(bytes).toString("base64url");
const sha256 = (bytes: Uint8Array): Uint8Array => new Uint8Array(createHash("sha256").update(bytes).digest());
const digest = (bytes: Uint8Array): string => b64(sha256(bytes));

function jcs(value: unknown): string {
  if (value === null || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "string") {
    for (let i = 0; i < value.length; i++) {
      const unit = value.charCodeAt(i);
      if (unit >= 0xd800 && unit <= 0xdbff) { const next = value.charCodeAt(i + 1); if (!(next >= 0xdc00 && next <= 0xdfff)) throw new TypeError("lone surrogate"); i++; }
      else if (unit >= 0xdc00 && unit <= 0xdfff) throw new TypeError("lone surrogate");
    }
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value) || !Number.isSafeInteger(value) || Object.is(value, -0)) throw new TypeError("unsafe number");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(jcs).join(",")}]`;
  if (typeof value !== "object" || Object.getPrototypeOf(value) !== Object.prototype) throw new TypeError("non-plain value");
  return `{${Object.keys(value).sort().map((key) => { const child = (value as Record<string, unknown>)[key]; if (child === undefined) throw new TypeError("undefined"); return `${JSON.stringify(key)}:${jcs(child)}`; }).join(",")}}`;
}

const here = dirname(fileURLToPath(import.meta.url));
const readJson = async <T>(path: string): Promise<T> => JSON.parse(await readFile(path, "utf8")) as T;
const record = (value: unknown, label: string): Record<string, unknown> => { if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label}: expected object`); return value as Record<string, unknown>; };
const list = (value: unknown, label: string): unknown[] => { if (!Array.isArray(value)) throw new Error(`${label}: expected array`); return value; };
function validateMatrix(positive: unknown, negative: unknown, states: unknown): void {
  const p = record(positive, "positive"); const scenarios = list(p.scenarios, "positive.scenarios"); if (scenarios.length !== 2) throw new Error("positive scenario count");
  const kinds = new Set(scenarios.map((value) => String(record(value, "scenario").kind))); if (kinds.size !== 2 || !kinds.has("kv") || !kinds.has("sql")) throw new Error("positive source matrix");
  for (const value of scenarios) { const scenario = record(value, "scenario"); if (scenario.testOnly !== true || scenario.canonicalEmail !== "Alice+Notes@example.com" || typeof scenario.sdJwtSalt !== "string") throw new Error("positive deterministic markers"); const preimages = record(scenario.preimages, "scenario.preimages"); if (!preimages.claimRedeemRequest || !preimages.claimRedeemOtpRequest || !preimages.policyChallengeResponse || !preimages.policySessionResponse) throw new Error("endpoint matrix incomplete"); const credential = record(scenario.credential, "credential"); const claims = record(credential.claims, "credential.claims"); if (claims._sd_alg !== "sha-256") throw new Error("SD-JWT algorithm marker"); const disclosures = list(credential.disclosures, "credential.disclosures"); if (disclosures.length !== 1 || record(disclosures[0], "disclosure").salt !== scenario.sdJwtSalt) throw new Error("SD-JWT salt marker"); }
  const n = record(negative, "negative"); const rows = list(n.cases, "negative.cases"); const ids = new Set<string>(); const known = new Set(["email","cid","policy","aead","schema","envelope","signature","jcs","encoding","did-key","source","binding","credential","state","capability","preimage","method","proof","sd-jwt"]);
  for (const value of rows) { const row = record(value, "negative row"); const id = row.id; if (typeof id !== "string" || ids.has(id)) throw new Error("negative IDs must be unique"); ids.add(id); if (row.expected !== "reject" || typeof row.kind !== "string" || !known.has(row.kind) || typeof row.target !== "string" || typeof row.mutation !== "string") throw new Error(`negative row incomplete: ${String(id)}`); const data = record(row.mutationData, `${String(id)}.mutationData`); if (typeof data.operation !== "string") throw new Error(`${String(id)} mutation operation`); const applies = list(row.appliesTo, `${String(id)}.appliesTo`); if (applies.length === 0 || applies.some((kind) => kind !== "kv" && kind !== "sql")) throw new Error(`${String(id)} applicability`); if (row.kind === "email" && typeof row.input !== "string") throw new Error(`${String(id)} email input`); if (row.kind === "method" && (typeof data.method !== "string" || typeof data.field !== "string" || typeof data.value !== "string")) throw new Error(`${String(id)} method mutation`); if (row.kind === "jcs" && (typeof data.jsonLiteral !== "string" || typeof data.numberKind !== "undefined" && typeof data.numberKind !== "string")) throw new Error(`${String(id)} number mutation`); if (row.kind === "sd-jwt" && typeof data.operation !== "string") throw new Error(`${String(id)} SD-JWT mutation`); }
  const s = record(states, "states"); const delivery = list(s.delivery, "states.delivery"); const names = new Set(delivery.map((flow) => String(record(flow, "delivery flow").name))); if (delivery.length !== 4 || names.size !== 4 || !["create-accepted","resend-accepted","resend-provider-failure","crash-after-provider-accept"].every((name) => names.has(name))) throw new Error("delivery state matrix incomplete"); if (JSON.stringify(s.invitation) !== JSON.stringify(["ABSENT","ACTIVE(v1)","REDEEMING(v1,redemption-001)","CONSUMED(v1)"]) || JSON.stringify(s.nonce) !== JSON.stringify(["ISSUED","VERIFYING","CONSUMED"]) || !list(s.session, "states.session").includes("EXPIRED") || !list(s.session, "states.session").includes("REVOKED")) throw new Error("state invariants"); const semantics = record(s.semantics, "states.semantics"); const race = record(semantics.sameRedemptionConcurrency, "same redemption"); if (race.attempts !== 20 || race.effectiveIssuances !== 1 || race.sameResultForSameId !== true) throw new Error("redemption invariant");
}

/** Loads and verifies the manifest and every byte-addressed bundle member. */
export async function loadFixtureBundle(baseDir = here): Promise<FixtureBundle> {
  const manifest = await readJson<FixtureManifest>(resolve(baseDir, "manifest.json"));
  const { manifestDigest: _ignored, ...manifestCore } = manifest;
  if (manifest.manifestDigest !== digest(text.encode(jcs(manifestCore)))) throw new Error("email-claim-v1 manifest digest mismatch");
  const specDir = resolve(baseDir, "../../../specs/email-claim-v1");
  for (const [name, expected] of Object.entries(manifest.files)) {
    const path = name === "README.md" || name === "domains.json" || name === "schemas.json" ? resolve(specDir, name) : resolve(baseDir, name);
    if (digest(await readFile(path)) !== expected) throw new Error(`email-claim-v1 file digest mismatch: ${name}`);
  }
  const positive = await readJson(resolve(baseDir, "positive.json"));
  const negative = await readJson(resolve(baseDir, "negative.json"));
  const states = await readJson(resolve(baseDir, "states.json"));
  validateMatrix(positive, negative, states);
  return {
    manifest,
    positive,
    negative,
    states,
    domains: await readJson(resolve(specDir, "domains.json")),
    schemas: await readJson(resolve(specDir, "schemas.json")),
  };
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))) {
  loadFixtureBundle().then(({ manifest }) => console.log(`email-claim-v1 loader: ${manifest.manifestDigest}`)).catch((error: unknown) => {
    console.error(error instanceof Error ? error.message : error);
    process.exitCode = 1;
  });
}
