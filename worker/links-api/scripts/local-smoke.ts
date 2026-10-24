// Exercises a running Worker (wrangler dev --local with a local D1; nothing is deployed):
//   node scripts/local-smoke.ts http://127.0.0.1:8799
// Prints one line per check; exit code 1 when any check fails.
// Against a local base (localhost, 127.0.0.1, [::1]) the requests carry a CF-Connecting-IP header, as the Worker's
// per-address limits expect. Against any other host no such header is sent: Cloudflare sets it itself.
import { MAX_LINK_BODY_BYTES } from "../src/config.ts";
import { AUDIENCE, clientAddressFor, filler, makeIssuer, signedCreate, signedDelete } from "../test/support/client.ts";

const base = process.argv[2] ?? "http://127.0.0.1:8799";
const ip = clientAddressFor(base);
let failures = 0;

async function send(request: Request): Promise<Response> {
  const url = request.url.replace(AUDIENCE, base);
  const hasBody = request.method !== "GET" && request.method !== "OPTIONS";
  return fetch(url, { method: request.method, headers: request.headers, body: hasBody ? await request.text() : null });
}

function check(name: string, ok: boolean, detail: unknown): void {
  if (!ok) {
    failures += 1;
  }
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}  ${JSON.stringify(detail)}`);
}

const get = (id: string) => new Request(`${AUDIENCE}/v1/links/${id}`);
const take = (id: string) => new Request(`${AUDIENCE}/v1/links/${id}/take`, { method: "POST" });

const issuer = makeIssuer();
const body = filler(2_000);
const created = await send(await signedCreate({ issuer, body, nowMs: Date.now(), ip }));
const { id } = (await created.json()) as { id: string };
check("create share (signed) -> 201", created.status === 201 && /^[a-z2-7]{26}$/.test(id), { status: created.status });

const read = await send(get(id));
const bytes = new Uint8Array(await read.arrayBuffer());
check("GET share -> 200 raw bytes + headers", read.status === 200 && bytes.length === body.length && read.headers.get("x-link-record") !== null && read.headers.get("cross-origin-resource-policy") === "same-site" && read.headers.get("access-control-allow-origin") === "*", { status: read.status, bytes: bytes.length });

const takeShare = await send(take(id));
check("take of a share -> 404 and removes nothing", takeShare.status === 404 && (await send(get(id))).status === 200, { status: takeShare.status });

const login = await send(await signedCreate({ type: "openkey-login", issuer: makeIssuer(), nowMs: Date.now(), ip }));
const loginId = ((await login.json()) as { id: string }).id;
const loginGet = await send(get(loginId));
const loginTake = await send(take(loginId));
const loginTakeAgain = await send(take(loginId));
check("openkey-login: GET 404, take 200, take again 404", loginGet.status === 404 && loginTake.status === 200 && loginTakeAgain.status === 404, [loginGet.status, loginTake.status, loginTakeAgain.status]);

const request = await signedCreate({ issuer: makeIssuer(), nowMs: Date.now(), ip });
const first = await send(request.clone());
const replay = await send(request.clone());
check("replayed create -> 409", first.status === 201 && replay.status === 409, [first.status, replay.status]);

const atLimit = await send(await signedCreate({ issuer: makeIssuer(), body: filler(MAX_LINK_BODY_BYTES), nowMs: Date.now(), ip }));
const overLimit = await send(await signedCreate({ issuer: makeIssuer(), body: filler(MAX_LINK_BODY_BYTES + 1), nowMs: Date.now(), ip }));
check(`body ${MAX_LINK_BODY_BYTES} -> 201, ${MAX_LINK_BODY_BYTES + 1} -> 413`, atLimit.status === 201 && overLimit.status === 413, [atLimit.status, overLimit.status]);

const badSig = await signedCreate({ issuer: makeIssuer(), nowMs: Date.now(), ip });
const parsed = JSON.parse(await badSig.text()) as { header: { type: string } };
parsed.header.type = "courier";
const tampered = await send(new Request(badSig.url, { method: "POST", headers: badSig.headers, body: JSON.stringify({ ...parsed, header: parsed.header, signature: { algorithm: "Ed25519", value: "A".repeat(86) }, body: "AQ" }) }));
check("bad signature / body -> 400 or 401", tampered.status === 400 || tampered.status === 401, { status: tampered.status });

const evil = await send(await signedCreate({ issuer: makeIssuer(), nowMs: Date.now(), ip, headers: { Origin: "https://evil.example" } }));
check("create from a foreign origin -> 403, no CORS headers", evil.status === 403 && evil.headers.get("access-control-allow-origin") === null, { status: evil.status });

const preflight = await send(new Request(`${AUDIENCE}/v1/links`, { method: "OPTIONS", headers: { Origin: "https://share.tinycloud.xyz", "Access-Control-Request-Method": "POST" } }));
check("preflight from share.tinycloud.xyz -> 204, Content-Type only", preflight.status === 204 && preflight.headers.get("access-control-allow-headers") === "Content-Type", { status: preflight.status });

const other = await send(await signedDelete({ issuer: makeIssuer(), id, nowMs: Date.now(), ip }));
const unknown = await send(await signedDelete({ issuer: makeIssuer(), id: "a".repeat(26), nowMs: Date.now(), ip }));
check("delete by another issuer == delete of an unknown id (404, same body)", other.status === 404 && unknown.status === 404 && (await other.text()) === (await unknown.text()), [other.status, unknown.status]);

const del = await send(await signedDelete({ issuer, id, nowMs: Date.now(), ip }));
const gone = await send(get(id));
const goneBody = await gone.text();
const unknownGet = await send(get("b".repeat(26)));
check("issuer deletes -> 204; then GET is the uniform 404", del.status === 204 && gone.status === 404 && goneBody === (await unknownGet.text()), [del.status, gone.status]);

console.log(failures === 0 ? "ALL CHECKS PASSED" : `${failures} CHECK(S) FAILED`);
process.exit(failures === 0 ? 0 : 1);
