import { createHash, createPrivateKey, createPublicKey } from "node:crypto";

// Mirrors opencredentials_witness/src/dstack.rs: the closed, unversioned
// issuer-signing path predates key-versioning and is the only purpose this
// harness derives.
export const ISSUER_SIGNING_KEY_PATH = "opencredentials/witness/signing-key";

const HEADER_TERMINATOR = Buffer.from("\r\n\r\n");
const PKCS8_ED25519_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

export function ed25519PublicKey(seed) {
  if (!Buffer.isBuffer(seed) || seed.length !== 32) throw new Error("ed25519PublicKey requires a 32-byte seed buffer");
  const pkcs8 = Buffer.concat([PKCS8_ED25519_PREFIX, seed]);
  const privateKey = createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
  return createPublicKey(privateKey).export({ format: "der", type: "spki" }).subarray(-32);
}

// The real witness derives every other dstack purpose from its requested
// path; only the issuer-signing path is pinned to the fixed local seed.
export function dstackKeyMaterial(requestedPath, issuerSeed) {
  if (requestedPath === ISSUER_SIGNING_KEY_PATH) return issuerSeed;
  return createHash("sha256").update(requestedPath).digest();
}

export function splitHttpMessage(raw) {
  const buffer = Buffer.isBuffer(raw) ? raw : Buffer.from(raw);
  const headerEnd = buffer.indexOf(HEADER_TERMINATOR);
  if (headerEnd === -1) return undefined;
  return { headerText: buffer.subarray(0, headerEnd).toString("latin1"), bodyStart: headerEnd + HEADER_TERMINATOR.length, buffer };
}

// Parses one dstack-shaped raw HTTP/1.1 request, returning undefined until
// the full declared Content-Length has arrived (a request can legitimately
// arrive split across TCP/Unix-socket reads).
export function parseDstackRequest(raw) {
  const split = splitHttpMessage(raw);
  if (split === undefined) return undefined;
  const { headerText, bodyStart, buffer } = split;
  const contentLength = Number(headerText.match(/\r?\ncontent-length:\s*(\d+)/i)?.[1] ?? 0);
  if (buffer.length - bodyStart < contentLength) return undefined;
  const path = headerText.split("\r\n", 1)[0]?.split(" ")[1];
  return { path, body: buffer.subarray(bodyStart, bodyStart + contentLength).toString("utf8") };
}

export function extractHttpResponseBody(raw) {
  const split = splitHttpMessage(raw);
  if (split === undefined) return undefined;
  return split.buffer.subarray(split.bodyStart);
}

// Builds the exact /Info and /GetKey JSON bodies the real dstack client
// (rust/opencredentials_witness/src/dstack.rs) expects.
export function buildDstackResponsePayload(path, body, issuerSeed) {
  if (path === "/Info") return { app_id: "hermetic-sharing-dstack-app", compose_hash: "hermetic-sharing-compose-hash", instance_id: "hermetic-sharing-instance" };
  if (path === "/GetKey") {
    let requestedPath = "";
    try { requestedPath = JSON.parse(body).path ?? ""; } catch { requestedPath = ""; }
    return { key: dstackKeyMaterial(requestedPath, issuerSeed).toString("hex") };
  }
  return undefined;
}

export function formatHttpResponse(payload) {
  const bytes = Buffer.from(JSON.stringify(payload));
  return Buffer.concat([Buffer.from(`HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: ${bytes.length}\r\nConnection: close\r\n\r\n`), bytes]);
}

export function formatGetKeyRequest(requestedPath) {
  const body = Buffer.from(JSON.stringify({ path: requestedPath }));
  return Buffer.concat([Buffer.from(`POST /GetKey HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: ${body.length}\r\nConnection: close\r\n\r\n`), body]);
}
