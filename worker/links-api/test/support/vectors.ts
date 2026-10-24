import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { addressBuckets } from "../../src/address.ts";
import { base64UrlDecode, base64UrlEncode, cidForBytes, hex, sha256, utf8 } from "../../src/bytes.ts";
import {
  ADDRESS_LIVE_CAP,
  LIMITS,
  LINK_TYPES,
  MAX_LINK_BODY_BYTES,
  MIN_BODY_BYTES,
  MIN_LIFE_SECONDS,
  NONCE_TTL_SECONDS,
  REQUEST_BODY_CAP_BYTES,
  TYPE_CONFIG,
  WINDOW_SECONDS,
  WORKERS_FREE_PLAN,
  type LinkType,
  type ServiceConfig,
} from "../../src/config.ts";
import { verifyStrict } from "../../src/ed25519.ts";
import { jcs } from "../../src/jcs.ts";
import { checkIssuer, checkLife, parseHeader, parseSignature } from "../../src/schemas.ts";
import {
  DOMAIN_DELETE,
  DOMAIN_HEADER,
  STATUS_BY_ERROR,
  addressHashes,
  handleRequestWithReason,
  rateKeys,
  type ServiceDeps,
} from "../../src/service.ts";
import { admit } from "../../src/sql-storage.ts";
import type { Adapter } from "./adapters.ts";
import { seedRows } from "./fixtures.ts";

const VECTORS_FILE = new URL("../vectors/short-links-api-vectors.json", import.meta.url);

/**
 * SHA-256 of the committed copy of `docs/specs/short-links-api-vectors.json` (contract Appendix B).
 * Updating the copy is a change of this one line plus the file.
 */
export const VECTORS_SHA256 = "59641c44536e5f53d7230205ff7d277bd5441cc8ddac10b7bee63f1d2358f3e6";

export function vectorsPath(): URL {
  return VECTORS_FILE;
}

export function fileSha256(path: URL | string): string {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

// ---------------------------------------------------------------------------------------------
// The parts of the vector file this harness reads. The file is a pinned fixture (its SHA-256 is
// checked before use), so it is read with one typed boundary.
// ---------------------------------------------------------------------------------------------

interface WireExpect {
  readonly status: number;
  readonly error?: string;
  readonly reason?: string;
}

interface Limit {
  readonly limit: number;
  readonly windowSeconds: number;
}

interface CreateVector {
  readonly name: string;
  readonly state: {
    readonly seenNonces: string[];
    readonly blocked: string[];
    readonly issuerRateLimited: boolean;
    readonly capacityFull: boolean;
    readonly addressBlocked: boolean;
    readonly addressRateLimited: boolean;
    readonly addressLiveFull: boolean;
    readonly origin?: string;
    readonly contentType?: string;
  };
  readonly request: unknown;
  readonly expect: WireExpect;
  readonly authorization?: string;
  readonly bodySynthesized?: { readonly length: number; readonly fillByte: number; readonly firstByte: number };
}

interface DeleteVector {
  readonly name: string;
  readonly urlId: string;
  readonly state: {
    readonly seenNonces: string[];
    readonly records: Record<string, { readonly issuer: string; readonly expiresAt: string }>;
    readonly addressBlocked: boolean;
    readonly origin?: string;
  };
  readonly request: unknown;
  readonly expect: WireExpect;
  readonly authorization?: string;
}

interface ApiKeyVector {
  readonly bearer: string;
  readonly stored: { readonly keyId: string; readonly service: string; readonly allowedTypes: LinkType[]; readonly secretSha256: string };
}

interface AdmissionCase {
  readonly name: string;
  readonly type: LinkType;
  readonly bodyBytes: number;
  readonly state: { readonly typeRows: number; readonly typeBytes: number; readonly addressRows: number; readonly addressBytes: number };
  readonly expect: string;
}

export interface Vectors {
  readonly meta: { readonly now: string; readonly audience: string };
  readonly constants: {
    readonly windowSeconds: number;
    readonly minLifeSeconds: number;
    readonly minBodyBytes: number;
    readonly requestBodyCapBytes: number;
    readonly maxLinkBodyBytes: number;
    readonly domains: Record<"header" | "delete", string>;
    readonly statusByError: Record<string, number>;
    readonly corsPostOrigins: string[];
    readonly types: Record<string, { readonly maxLifeS: number; readonly readOnce: boolean }>;
  };
  readonly sizes: { readonly maxLinkBodyBytes: number; readonly requestBodyCapBytes: number };
  readonly records: {
    readonly name: string;
    readonly now: string;
    readonly contentKeyB64u: string | null;
    readonly record: unknown;
    readonly expect: WireExpect;
    readonly bodySynthesized?: { readonly length: number; readonly fillByte: number; readonly firstByte: number };
  }[];
  readonly apiKeys: ApiKeyVector[];
  readonly ids: { readonly name: string; readonly id: string; readonly expect: { readonly valid: boolean; readonly normalized?: string } }[];
  readonly bodyHash: {
    readonly name: string;
    readonly bodyB64u: string;
    readonly expect: { readonly size: number; readonly cid: string; readonly differsFromCidOf?: string };
  }[];
  readonly signatures: {
    readonly name: string;
    readonly object: unknown;
    readonly jcs: string;
    readonly domain: "header" | "delete";
    readonly preimageHex: string;
    readonly digestHex: string;
    readonly signature: unknown;
    readonly verifyAsIssuer: string;
    readonly expect: { readonly valid: boolean };
  }[];
  readonly ed25519Strict: { readonly name: string; readonly publicKeyHex: string; readonly messageHex: string; readonly signatureHex: string; readonly expect: { readonly valid: boolean } }[];
  readonly headers: { readonly name: string; readonly mode: "signed" | "service"; readonly header: unknown; readonly expect: WireExpect }[];
  readonly create: CreateVector[];
  readonly delete: DeleteVector[];
  readonly read: { readonly type: LinkType; readonly sequence: string[]; readonly expect: number[] }[];
  readonly addressBuckets: { readonly address: string; readonly expect: { readonly rateKey: string; readonly liveKey: string } }[];
  readonly admission: { readonly cases: AdmissionCase[] };
  readonly nonceSweep: { readonly name: string; readonly ttlSeconds: number; readonly steps: { readonly op: string; readonly key: string; readonly t: number }[]; readonly expect: (boolean | null)[] }[];
  readonly nonceStore: {
    readonly ttlSeconds: number;
    readonly cases: { readonly name: string; readonly issuer: string; readonly nonce: string; readonly atSeconds: number; readonly seenBefore: boolean; readonly expect: string }[];
  };
  readonly rateLimits: {
    readonly perIssuer: { readonly create: Limit[]; readonly delete: Limit[] };
    readonly perClientAddress: { readonly createAnyIssuer: Limit[]; readonly invalidRequests: Limit[]; readonly read: Limit[]; readonly delete: Limit[] };
    readonly perApiKey: { readonly create: Limit[]; readonly delete: Limit[] };
    readonly windowSequences: { readonly name: string; readonly limit: number; readonly windowSeconds: number; readonly timesSeconds: number[]; readonly expectAllowed: boolean[] }[];
    readonly globalQuotaPerType: Record<LinkType, { readonly rows: number; readonly bytes: number }>;
  };
}

export function loadVectors(path: URL | string = VECTORS_FILE): Vectors {
  // Pinned fixture: the SHA-256 pin is verified by the caller before the contents are trusted.
  return JSON.parse(readFileSync(path, "utf8")) as Vectors;
}

export interface VectorResult {
  readonly group: string;
  readonly name: string;
  readonly ok: boolean;
  readonly expected?: unknown;
  readonly got?: unknown;
  readonly note?: string;
}

/** Groups that describe reader-side behaviour (viewer, CLI, node, witness), which the service does not implement. */
export const READER_SIDE_GROUPS = ["records", "resolve", "links", "linkChoice", "deliveryAdmission"] as const;

const CLIENT_ADDRESS = "192.0.2.77";
const BASE = "https://api.tinycloud.xyz";

const CONFIG: ServiceConfig = {
  audience: BASE,
  corsOrigins: ["https://share.tinycloud.xyz"],
  takeOrigins: [],
  addressSalt: "vector-run-salt-0123456789",
  kill: { create: false, read: false, take: false, delete: false },
  clientAddressHeader: "CF-Connecting-IP",
};

interface Run {
  readonly vectors: Vectors;
  readonly adapter: Adapter;
  readonly nowMs: number;
  readonly results: VectorResult[];
}

function record(run: Run, group: string, name: string, ok: boolean, expected?: unknown, got?: unknown, note?: string): void {
  run.results.push({ group, name, ok, ...(ok ? {} : { expected, got }), ...(note ? { note } : {}) });
}

function sameJson(a: unknown, b: unknown): boolean {
  return JSON.stringify(a) === JSON.stringify(b);
}

function service(run: Run): ServiceDeps {
  return {
    storage: run.adapter.storage(),
    config: CONFIG,
    usage: { plan: WORKERS_FREE_PLAN, tally: null, statsEveryMinutes: 5 },
    now: () => run.nowMs,
    log: () => undefined,
  };
}

function asObject(value: unknown): Record<string, unknown> | null {
  return typeof value === "object" && value !== null && !Array.isArray(value) ? Object.fromEntries(Object.entries(value)) : null;
}

interface HeaderInfo {
  readonly type: LinkType | null;
  readonly issuer: string | null;
  readonly expiresAt: string | null;
}

function headerOf(request: unknown): HeaderInfo | null {
  const header = asObject(asObject(request)?.["header"]);
  if (header === null) {
    return null;
  }
  const type = LINK_TYPES.find((t) => t === header["type"]) ?? null;
  const issuer = header["issuer"];
  const expiresAt = header["expiresAt"];
  return {
    type,
    issuer: typeof issuer === "string" ? issuer : null,
    expiresAt: typeof expiresAt === "string" ? expiresAt : null,
  };
}

function stringField(value: unknown, key: string): string | null {
  const field = asObject(value)?.[key];
  return typeof field === "string" ? field : null;
}

function synthesizedBody(spec: { length: number; fillByte: number; firstByte: number }): Uint8Array {
  const bytes = new Uint8Array(spec.length).fill(spec.fillByte);
  bytes[0] = spec.firstByte;
  return bytes;
}

async function wireOutcome(deps: ServiceDeps, request: Request): Promise<{ got: WireExpect; json: unknown; reason: string | null }> {
  const outcome = await handleRequestWithReason(request, deps);
  const text = await outcome.response.text();
  const json: unknown = text.length > 0 ? JSON.parse(text) : null;
  const error = stringField(json, "error");
  return {
    got: error === null ? { status: outcome.response.status } : { status: outcome.response.status, error },
    json,
    reason: outcome.reason,
  };
}

function matches(expect: WireExpect, got: WireExpect, reason: string | null): boolean {
  if (expect.status !== got.status || expect.error !== got.error) {
    return false;
  }
  return expect.reason === undefined || expect.reason === reason;
}

function authorization(vector: { authorization?: string }, apiKey: ApiKeyVector): string | null {
  return vector.authorization ? vector.authorization.replace("<bearer from apiKeys[0]>", apiKey.bearer) : null;
}

function createRequest(vector: CreateVector, apiKey: ApiKeyVector): Request {
  const headers = new Headers({ "Content-Type": vector.state.contentType ?? "application/json", "CF-Connecting-IP": CLIENT_ADDRESS });
  if (vector.state.origin) {
    headers.set("Origin", vector.state.origin);
  }
  const bearer = authorization(vector, apiKey);
  if (bearer !== null) {
    headers.set("Authorization", bearer);
  }
  const body = vector.bodySynthesized
    ? { ...asObject(vector.request), body: base64UrlEncode(synthesizedBody(vector.bodySynthesized)) }
    : vector.request;
  return new Request(`${BASE}/v1/links`, { method: "POST", headers, body: JSON.stringify(body) });
}

async function prepare(run: Run, state: { seenNonces: string[]; addressBlocked: boolean }, apiKey: ApiKeyVector): Promise<ServiceDeps> {
  await run.adapter.reset();
  const deps = service(run);
  const nowSeconds = Math.floor(run.nowMs / 1000);
  await deps.storage.addApiKey(
    { keyId: apiKey.stored.keyId, service: apiKey.stored.service, allowedTypes: apiKey.stored.allowedTypes, secretSha256: apiKey.stored.secretSha256 },
    nowSeconds,
  );
  for (const entry of state.seenNonces) {
    await deps.storage.claimNonce("link", base64UrlEncode(await sha256(utf8(entry))), NONCE_TTL_SECONDS, nowSeconds);
  }
  if (state.addressBlocked) {
    await deps.storage.setBlocked("address", (await addressHashes(CONFIG, CLIENT_ADDRESS)).liveHash, "vector", nowSeconds);
  }
  return deps;
}

async function runCreate(run: Run, apiKey: ApiKeyVector): Promise<void> {
  const nowSeconds = Math.floor(run.nowMs / 1000);
  for (const vector of run.vectors.create) {
    const deps = await prepare(run, vector.state, apiKey);
    const header = headerOf(vector.request);
    const hashes = await addressHashes(CONFIG, CLIENT_ADDRESS);
    for (const issuer of vector.state.blocked) {
      await deps.storage.setBlocked("issuer", issuer, "vector", nowSeconds);
    }
    if (vector.state.issuerRateLimited && header?.issuer) {
      for (const window of LIMITS.issuerCreate) {
        for (let i = 0; i < window.limit; i++) {
          await deps.storage.hit(rateKeys.issuerCreate(header.issuer, window.windowSeconds), window.limit, window.windowSeconds, nowSeconds);
        }
      }
    }
    if (vector.state.addressRateLimited) {
      const window = LIMITS.addressCreate[0];
      for (let i = 0; i < window.limit; i++) {
        await deps.storage.hit(rateKeys.addressCreate(hashes.rateHash, window.windowSeconds), window.limit, window.windowSeconds, nowSeconds);
      }
    }
    if (vector.state.capacityFull && header?.type) {
      await seedRows(run.adapter.driver, { idPrefix: "fill", type: header.type, count: TYPE_CONFIG[header.type].quotaRows, size: 0, address: "filler", expiresAt: nowSeconds + 3600 });
    }
    if (vector.state.addressLiveFull) {
      await seedRows(run.adapter.driver, { idPrefix: "addr", type: "courier", count: ADDRESS_LIVE_CAP.rows, size: 0, address: hashes.liveHash, expiresAt: nowSeconds + 3600 });
    }
    const { got, json, reason } = await wireOutcome(deps, createRequest(vector, apiKey));
    let ok = matches(vector.expect, got, reason);
    if (ok && got.status === 201) {
      ok = /^[a-z2-7]{26}$/.test(stringField(json, "id") ?? "") && stringField(json, "expiresAt") === header?.expiresAt && Object.keys(asObject(json) ?? {}).length === 2;
    }
    record(run, "create", vector.name, ok, vector.expect, { ...got, reason });
  }
}

async function runDelete(run: Run, apiKey: ApiKeyVector): Promise<void> {
  const nowSeconds = Math.floor(run.nowMs / 1000);
  for (const vector of run.vectors.delete) {
    const deps = await prepare(run, vector.state, apiKey);
    for (const [id, info] of Object.entries(vector.state.records)) {
      await deps.storage.put(
        {
          id,
          type: "share",
          issuer: info.issuer,
          issuedAt: nowSeconds,
          expiresAt: Math.floor(Date.parse(info.expiresAt) / 1000),
          size: 8,
          bodyCid: "bafkreia2a2r36os6e5f44r336qxrufkiadw776sv2gxz5mt45yaefqmrl4",
          headerJcs: "{}",
          signature: null,
          body: new Uint8Array(8),
          addressHash: "seed",
        },
        nowSeconds - 10_000,
      );
    }
    const headers = new Headers({ "Content-Type": "application/json", "CF-Connecting-IP": CLIENT_ADDRESS });
    if (vector.state.origin) {
      headers.set("Origin", vector.state.origin);
    }
    const bearer = authorization(vector, apiKey);
    if (bearer !== null) {
      headers.set("Authorization", bearer);
    }
    const request = new Request(`${BASE}/v1/links/${vector.urlId}/delete`, { method: "POST", headers, body: JSON.stringify(vector.request) });
    const { got, reason } = await wireOutcome(deps, request);
    record(run, "delete", vector.name, matches(vector.expect, got, reason), vector.expect, { ...got, reason });
  }
}

async function runRead(run: Run, apiKey: ApiKeyVector): Promise<void> {
  for (const vector of run.vectors.read) {
    const source = run.vectors.create.slice(0, 3).find((c) => headerOf(c.request)?.type === vector.type);
    if (!source) {
      record(run, "read", vector.type, false, "a create vector of this type", null);
      continue;
    }
    const deps = await prepare(run, { seenNonces: [], addressBlocked: false }, apiKey);
    const created = await wireOutcome(deps, createRequest(source, apiKey));
    const id = stringField(created.json, "id") ?? "";
    const statuses: number[] = [];
    for (const step of vector.sequence) {
      const request =
        step === "GET"
          ? new Request(`${BASE}/v1/links/${id}`, { headers: { "CF-Connecting-IP": CLIENT_ADDRESS } })
          : new Request(`${BASE}/v1/links/${id}/take`, { method: "POST", headers: { "CF-Connecting-IP": CLIENT_ADDRESS } });
      statuses.push((await handleRequestWithReason(request, deps)).response.status);
    }
    record(run, "read", vector.type, sameJson(statuses, vector.expect), vector.expect, statuses);
  }
}

function runHeaders(run: Run): void {
  const audience = run.vectors.meta.audience;
  for (const vector of run.vectors.headers) {
    const parsed = parseHeader(vector.header, vector.mode, audience);
    let got: WireExpect = { status: 200 };
    if (!parsed.ok) {
      got = { status: 400, error: "invalid_request", reason: parsed.reason };
    } else {
      const life = checkLife(parsed.header, run.nowMs);
      if (life !== null) {
        got = { status: 400, error: "invalid_request", reason: life };
      }
    }
    record(run, "headers", vector.name, sameJson(vector.expect, got), vector.expect, got);
  }
}

async function runSignatures(run: Run): Promise<void> {
  for (const vector of run.vectors.signatures) {
    const preimage = utf8(run.vectors.constants.domains[vector.domain] + jcs(vector.object));
    const digest = await sha256(preimage);
    const issuer = checkIssuer(vector.verifyAsIssuer, "signed");
    const bytes = parseSignature(vector.signature);
    const valid = issuer.ok && issuer.publicKey !== null && bytes !== null && verifyStrict(issuer.publicKey, digest, bytes);
    const same = jcs(vector.object) === vector.jcs && hex(preimage) === vector.preimageHex && hex(digest) === vector.digestHex;
    record(run, "signatures", vector.name, same && valid === vector.expect.valid, vector.expect, { valid, bytesMatch: same });
  }
}

function runEd25519(run: Run): void {
  const fromHex = (h: string) => Uint8Array.from(Buffer.from(h, "hex"));
  for (const vector of run.vectors.ed25519Strict) {
    const valid = verifyStrict(fromHex(vector.publicKeyHex), fromHex(vector.messageHex), fromHex(vector.signatureHex));
    record(run, "ed25519Strict", vector.name, valid === vector.expect.valid, vector.expect, { valid });
  }
}

async function runSmallGroups(run: Run): Promise<void> {
  for (const vec of run.vectors.ids) {
    const lower = vec.id.toLowerCase();
    const valid = /^[a-z2-7]{26}$/.test(lower);
    const got = valid ? { valid, normalized: lower } : { valid };
    record(run, "ids", vec.name, sameJson(vec.expect, got), vec.expect, got);
  }
  for (const vec of run.vectors.bodyHash) {
    const bytes = base64UrlDecode(vec.bodyB64u);
    const { differsFromCidOf, ...fields } = vec.expect;
    const got = bytes ? { size: bytes.length, cid: await cidForBytes(bytes) } : null;
    const other = differsFromCidOf === undefined ? null : run.vectors.bodyHash.find((b) => b.name === `cid of ${differsFromCidOf} body`);
    const differs = other === null || (other !== undefined && got !== null && other.expect.cid !== got.cid);
    record(run, "bodyHash", vec.name, sameJson(fields, got) && differs, vec.expect, got);
  }
  for (const vec of run.vectors.addressBuckets) {
    const got = addressBuckets(vec.address);
    record(run, "addressBuckets", JSON.stringify(vec.address), got.rateKey === vec.expect.rateKey && got.liveKey === vec.expect.liveKey, vec.expect, got);
  }
}

async function runAdmission(run: Run): Promise<void> {
  const storage = run.adapter.storage();
  const now = 1_800_000_000;
  for (const c of run.vectors.admission.cases) {
    await run.adapter.reset();
    // Address rows are of another type, so the type totals and the address totals can be set apart.
    const otherType: LinkType = c.type === "courier" ? "share" : "courier";
    const typeHeavy = c.state.typeRows > 0 ? 1 : 0;
    const addressHeavy = c.state.addressRows > 0 ? 1 : 0;
    await seedRows(run.adapter.driver, { idPrefix: "t", type: c.type, count: c.state.typeRows - typeHeavy, size: 0, address: "filler", expiresAt: now + 3600 });
    await seedRows(run.adapter.driver, { idPrefix: "T", type: c.type, count: typeHeavy, size: c.state.typeBytes, address: "filler", expiresAt: now + 3600 });
    await seedRows(run.adapter.driver, { idPrefix: "a", type: otherType, count: c.state.addressRows - addressHeavy, size: 0, address: "target", expiresAt: now + 3600 });
    await seedRows(run.adapter.driver, { idPrefix: "A", type: otherType, count: addressHeavy, size: c.state.addressBytes, address: "target", expiresAt: now + 3600 });
    const outcome = await storage.put(
      { id: "z".repeat(26), type: c.type, issuer: "i", issuedAt: now, expiresAt: now + 600, size: c.bodyBytes, bodyCid: "c", headerJcs: "{}", signature: null, body: new Uint8Array(c.bodyBytes), addressHash: "target" },
      now,
    );
    const rule = admit(c.state, c.type, c.bodyBytes);
    record(run, "admission", c.name, outcome === c.expect && rule === c.expect, c.expect, { storage: outcome, rule });
  }
}

async function runNonceAndRates(run: Run): Promise<void> {
  const storage = run.adapter.storage();
  for (const [index, vec] of run.vectors.nonceSweep.entries()) {
    await run.adapter.reset();
    const got: (boolean | null)[] = [];
    for (const step of vec.steps) {
      if (step.op === "claim") {
        got.push(await storage.claimNonce("vector", step.key, vec.ttlSeconds, step.t));
      } else {
        await storage.sweep(step.t);
        got.push(null);
      }
    }
    record(run, "nonceSweep", `${index}: ${vec.name}`, sameJson(vec.expect, got), vec.expect, got);
  }
  for (const c of run.vectors.nonceStore.cases) {
    await run.adapter.reset();
    const key = `${c.issuer}|${c.nonce}`;
    const windowCase = c.expect === "accepted-by-store-refused-by-window";
    if (c.seenBefore || windowCase) {
      await storage.claimNonce("vector", key, run.vectors.nonceStore.ttlSeconds, 0);
    }
    const claimed = await storage.claimNonce("vector", key, run.vectors.nonceStore.ttlSeconds, c.atSeconds);
    const got = claimed ? (windowCase ? c.expect : "accepted") : "replayed";
    record(run, "nonceStore", c.name, got === c.expect, c.expect, got);
  }
  for (const seq of run.vectors.rateLimits.windowSequences) {
    await run.adapter.reset();
    const got: boolean[] = [];
    for (const t of seq.timesSeconds) {
      got.push((await storage.hit("seq", seq.limit, seq.windowSeconds, t)).allowed);
    }
    record(run, "rateLimits.windowSequences", seq.name, sameJson(seq.expectAllowed, got), seq.expectAllowed, got);
  }
}

function runConstants(run: Run): void {
  const { constants, rateLimits } = run.vectors;
  const shaped = (limits: readonly Limit[]) => limits.map(({ limit, windowSeconds }) => ({ limit, windowSeconds }));
  const checks: [string, unknown, unknown, string?][] = [
    ["windowSeconds", constants.windowSeconds, WINDOW_SECONDS],
    ["minLifeSeconds", constants.minLifeSeconds, MIN_LIFE_SECONDS],
    ["minBodyBytes", constants.minBodyBytes, MIN_BODY_BYTES],
    ["domain header", constants.domains.header, DOMAIN_HEADER],
    ["domain delete", constants.domains.delete, DOMAIN_DELETE],
    ["statusByError", constants.statusByError, { ...STATUS_BY_ERROR }],
    ["corsPostOrigins", constants.corsPostOrigins, [...CONFIG.corsOrigins]],
    ["nonce ttl", run.vectors.nonceStore.ttlSeconds, NONCE_TTL_SECONDS],
    ["perIssuer create", rateLimits.perIssuer.create, shaped(LIMITS.issuerCreate)],
    ["perIssuer delete", rateLimits.perIssuer.delete, shaped(LIMITS.issuerDelete)],
    ["address create", rateLimits.perClientAddress.createAnyIssuer, shaped(LIMITS.addressCreate)],
    ["address refused", rateLimits.perClientAddress.invalidRequests, shaped([LIMITS.addressRefused])],
    ["address read", rateLimits.perClientAddress.read, shaped([LIMITS.addressRead])],
    ["address delete", rateLimits.perClientAddress.delete, shaped([LIMITS.addressDelete])],
    ["api key create", rateLimits.perApiKey.create, shaped([LIMITS.apiKeyCreate])],
    ["api key delete", rateLimits.perApiKey.delete, shaped([LIMITS.apiKeyDelete])],
  ];
  checks.push(
    ["maxLinkBodyBytes", constants.maxLinkBodyBytes, MAX_LINK_BODY_BYTES],
    ["requestBodyCapBytes", constants.requestBodyCapBytes, REQUEST_BODY_CAP_BYTES],
    ["sizes.maxLinkBodyBytes", run.vectors.sizes.maxLinkBodyBytes, MAX_LINK_BODY_BYTES],
    ["sizes.requestBodyCapBytes", run.vectors.sizes.requestBodyCapBytes, REQUEST_BODY_CAP_BYTES],
  );
  for (const [type, spec] of Object.entries(constants.types)) {
    const config = LINK_TYPES.find((t) => t === type);
    if (config === undefined) {
      continue;
    }
    checks.push(
      [`${type} maxLife`, spec.maxLifeS, TYPE_CONFIG[config].maxLifeSeconds],
      [`${type} readOnce`, spec.readOnce, TYPE_CONFIG[config].readOnce],
      [`${type} quota`, rateLimits.globalQuotaPerType[config], { rows: TYPE_CONFIG[config].quotaRows, bytes: TYPE_CONFIG[config].quotaBytes }],
    );
  }
  for (const [name, expected, got, note] of checks) {
    record(run, "constants", name, sameJson(expected, got), expected, got, note);
  }
}

/**
 * The reader-side `records` vectors that need no sealed-body opening (the body-size boundaries): the checks the
 * service shares with readers (header, size, limit, minimum, CID, signature, expiry). Issuer binding and the other
 * vectors that open the seal belong to the readers.
 */
async function runRecordBoundaries(run: Run): Promise<void> {
  for (const vec of run.vectors.records) {
    if (vec.contentKeyB64u !== null || !vec.bodySynthesized) {
      continue;
    }
    const record_ = asObject(vec.record);
    const signed = record_ !== null && "signature" in record_;
    const parsed = parseHeader(record_?.["header"], signed ? "signed" : "service", run.vectors.meta.audience);
    let got: WireExpect = { status: 200 };
    if (!parsed.ok) {
      got = { status: 400, error: "invalid_request", reason: parsed.reason };
    } else {
      const header = parsed.header;
      const body = synthesizedBody(vec.bodySynthesized);
      if (!signed && header.type !== "openkey-login") {
        got = { status: 400, error: "invalid_request", reason: "unsigned_not_allowed" };
      } else if (body.length !== header.size) {
        got = { status: 400, error: "invalid_request", reason: "size_mismatch" };
      } else if (body.length > MAX_LINK_BODY_BYTES) {
        got = { status: 413, error: "too_large", reason: "body_over_cap" };
      } else if (body.length < MIN_BODY_BYTES) {
        got = { status: 400, error: "invalid_request", reason: "body_too_small" };
      } else if ((await cidForBytes(body)) !== header.bodyCid) {
        got = { status: 400, error: "invalid_request", reason: "body_hash_mismatch" };
      } else if (signed && !(await verifyHeaderSignature(header, record_?.["signature"], parsed.issuerKey, run.vectors.constants.domains.header))) {
        got = { status: 401, error: "invalid_signature", reason: "bad_signature" };
      } else if (Date.parse(header.expiresAt) <= Date.parse(vec.now)) {
        got = { status: 404, error: "not_found", reason: "expired" };
      }
    }
    record(run, "records (size boundaries)", vec.name, sameJson(vec.expect, got), vec.expect, got);
  }
}

async function verifyHeaderSignature(header: unknown, signature: unknown, key: Uint8Array | null, domain: string): Promise<boolean> {
  const bytes = parseSignature(signature);
  return bytes !== null && key !== null && verifyStrict(key, await sha256(utf8(domain + jcs(header))), bytes);
}

/** Runs every service-level vector group on one adapter. Reader-side groups are not run here. */
export async function runServiceVectors(vectors: Vectors, adapter: Adapter): Promise<VectorResult[]> {
  const run: Run = { vectors, adapter, nowMs: Date.parse(vectors.meta.now), results: [] };
  const apiKey = vectors.apiKeys[0];
  if (!apiKey) {
    throw new Error("vectors: apiKeys[0] missing");
  }
  runHeaders(run);
  await runRecordBoundaries(run);
  await runSignatures(run);
  runEd25519(run);
  await runSmallGroups(run);
  runConstants(run);
  await runAdmission(run);
  await runNonceAndRates(run);
  await runCreate(run, apiKey);
  await runDelete(run, apiKey);
  await runRead(run, apiKey);
  await adapter.reset();
  return run.results;
}

export function summarize(results: readonly VectorResult[]): Record<string, { total: number; passed: number }> {
  const out: Record<string, { total: number; passed: number }> = {};
  for (const r of results) {
    const entry = (out[r.group] ??= { total: 0, passed: 0 });
    entry.total += 1;
    entry.passed += r.ok ? 1 : 0;
  }
  return out;
}
