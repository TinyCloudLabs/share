import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { WORKERS_FREE_PLAN, type ServiceConfig } from "../src/config.ts";
import { READ_AUTH_HEADER, evaluateReadAuth } from "../src/read-auth.ts";
import { parseReadSigners } from "../src/read-signers.ts";
import { handleRequest, type ServiceDeps } from "../src/service.ts";
import { createSqliteAdapter, type Adapter } from "./support/adapters.ts";
import { AUDIENCE, get, makeIssuer, signedCreate } from "./support/client.ts";
import { TEST_NODE_DID, readAuthValue, testNodeKey } from "./support/read-auth-client.ts";

/**
 * Contract section 4.11 (Validation) and section 2.2 rule (d): the `TinyCloud-Read-Auth` value decodes to the
 * JCS bytes of its own parsed value, and nothing else is accepted. A byte order mark is not part of JCS, so a
 * value that decodes to a BOM followed by the JCS bytes is not a valid header.
 */

const NOW = Date.parse("2026-10-24T12:00:00.000Z");
const BOM = Buffer.from([0xef, 0xbb, 0xbf]);
const SIGNERS = parseReadSigners([{ label: "service:node", did: TEST_NODE_DID }]);
const ID = "c".repeat(26);

/** The header value for `bytes` placed on the wire as unpadded base64url. */
const valueOf = (bytes: Buffer) => bytes.toString("base64url");
const jcsBytes = async (id = ID) => Buffer.from(await readAuthValue({ key: testNodeKey, id, nowMs: NOW }), "base64url");

const evaluate = (headerValue: string | null, id = ID) =>
  evaluateReadAuth({ headerValue, method: "GET", pathname: `/v1/links/${id}`, search: "", audience: AUDIENCE, nowMs: NOW, signers: SIGNERS });

describe("TinyCloud-Read-Auth: the decoded bytes must be the JCS bytes", () => {
  it("accepts the JCS bytes (the control: the signature, signer and window are valid)", async () => {
    expect(await evaluate(valueOf(await jcsBytes()))).toEqual({ authenticated: true, label: "service:node" });
  });

  it("refuses a leading UTF-8 byte order mark before the JCS bytes as malformed", async () => {
    const bytes = await jcsBytes();
    expect(await evaluate(valueOf(Buffer.concat([BOM, bytes])))).toEqual({ authenticated: false, reason: "malformed" });
  });

  it.each([
    ["two byte order marks", (b: Buffer) => Buffer.concat([BOM, BOM, b])],
    ["a byte order mark after the JCS bytes", (b: Buffer) => Buffer.concat([b, BOM])],
    ["a UTF-16 little-endian mark before the JCS bytes", (b: Buffer) => Buffer.concat([Buffer.from([0xff, 0xfe]), b])],
    ["a UTF-16 big-endian mark before the JCS bytes", (b: Buffer) => Buffer.concat([Buffer.from([0xfe, 0xff]), b])],
    ["a leading space", (b: Buffer) => Buffer.concat([Buffer.from(" "), b])],
    ["a trailing newline", (b: Buffer) => Buffer.concat([b, Buffer.from("\n")])],
    ["a zero-width no-break space written as an escape inside a value", (b: Buffer) => Buffer.from(b.toString("utf8").replace('"issuedAt":"', '"issuedAt":"\\ufeff'))],
  ])("keeps refusing %s", async (_name, mutate) => {
    const result = await evaluate(valueOf(mutate(await jcsBytes())));
    expect(result).toEqual({ authenticated: false, reason: "malformed" });
  });

  it("a header with a byte order mark is refused the same way as other malformed headers: an ordinary read", async () => {
    const bytes = await jcsBytes();
    const withBom = await evaluate(valueOf(Buffer.concat([BOM, bytes])));
    const notBase64 = await evaluate("not-base64url!");
    const extraSpace = await evaluate(valueOf(Buffer.concat([Buffer.from(" "), bytes])));
    expect(withBom).toEqual(notBase64);
    expect(withBom).toEqual(extraSpace);
  });
});

describe("a request whose header carries a byte order mark", () => {
  let adapter: Adapter;
  let deps: ServiceDeps;
  let counter: number;

  beforeAll(async () => {
    adapter = await createSqliteAdapter();
  });
  afterAll(async () => {
    await adapter.close();
  });
  beforeEach(async () => {
    await adapter.reset();
    counter = 0;
    const config: ServiceConfig = {
      audience: AUDIENCE,
      corsOrigins: ["https://share.tinycloud.xyz"],
      takeOrigins: [],
      addressSalt: "read-auth-bom-salt-0123456789",
      kill: { create: false, read: false, take: false, delete: false },
      clientAddressHeader: "CF-Connecting-IP",
      readSigners: SIGNERS,
    };
    deps = { storage: adapter.storage(), config, usage: { plan: WORKERS_FREE_PLAN, tally: null, statsEveryMinutes: 1 }, now: () => NOW, log: () => undefined };
  });

  const ip = () => `198.51.100.${(counter += 1)}`;
  const shape = async (response: Response) => ({
    status: response.status,
    headers: [...response.headers].sort(),
    body: Buffer.from(await response.arrayBuffer()).toString("hex"),
  });

  it("is served as an ordinary read: same status, headers and body as a read with no header, and it is not counted as authenticated", async () => {
    const created = await handleRequest(await signedCreate({ issuer: makeIssuer(), nowMs: NOW }), deps);
    const { id } = (await created.json()) as { id: string };
    const bytes = await jcsBytes(id);

    const plain = await shape(await handleRequest(get(id, ip()), deps));
    const bom = await shape(
      await handleRequest(new Request(`${AUDIENCE}/v1/links/${id}`, { headers: { "CF-Connecting-IP": ip(), [READ_AUTH_HEADER]: valueOf(Buffer.concat([BOM, bytes])) } }), deps),
    );
    expect(bom).toEqual(plain);
    expect(plain.status).toBe(200);
    expect((await deps.storage.readCounts())["reads.authenticated"] ?? 0).toBe(0);

    // The same header without the byte order mark is recognised: the counter moves.
    const good = await shape(
      await handleRequest(new Request(`${AUDIENCE}/v1/links/${id}`, { headers: { "CF-Connecting-IP": ip(), [READ_AUTH_HEADER]: valueOf(bytes) } }), deps),
    );
    expect(good).toEqual(plain);
    expect((await deps.storage.readCounts())["reads.authenticated"] ?? 0).toBe(1);
  });

  it("uses the per-address limit, so a stream of such reads cannot use the label's bucket", async () => {
    const created = await handleRequest(await signedCreate({ issuer: makeIssuer(), nowMs: NOW }), deps);
    const { id } = (await created.json()) as { id: string };
    const value = valueOf(Buffer.concat([BOM, await jcsBytes(id)]));
    const address = ip();
    let refusedAt = 0;
    for (let i = 1; i <= 130; i++) {
      const response = await handleRequest(new Request(`${AUDIENCE}/v1/links/${id}`, { headers: { "CF-Connecting-IP": address, [READ_AUTH_HEADER]: value } }), deps);
      if (response.status === 429) {
        refusedAt = i;
        break;
      }
    }
    expect(refusedAt).toBe(121);
  });
});
