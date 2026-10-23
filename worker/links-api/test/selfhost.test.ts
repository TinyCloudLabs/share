import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { AddressInfo } from "node:net";
import { createSelfHost, SOCKET_ADDRESS_HEADER, type SelfHost } from "../src/selfhost-server.ts";
import { AUDIENCE, filler, makeIssuer, signedCreate, signedDelete } from "./support/client.ts";

describe("self-host build: one SQLite file behind the same service code", () => {
  let host: SelfHost;
  let origin: string;
  const lines: string[] = [];

  beforeAll(async () => {
    host = createSelfHost({ env: { ADDRESS_SALT: "selfhost-salt-0123456789" }, dbPath: ":memory:", log: (line) => lines.push(line) });
    await new Promise<void>((resolve) => host.server.listen(0, "127.0.0.1", resolve));
    origin = `http://127.0.0.1:${(host.server.address() as AddressInfo).port}`;
  });
  afterAll(async () => {
    await host.close();
  });

  /** The service routes on the path only; the test sends the request built for the API origin to the local port. */
  const send = async (request: Request): Promise<Response> => {
    const url = new URL(request.url.replace(AUDIENCE, origin));
    return fetch(url, { method: request.method, headers: request.headers, body: request.method === "GET" ? null : await request.text() });
  };

  it("creates, reads, takes and deletes over real HTTP", async () => {
    const nowMs = Date.now();
    const issuer = makeIssuer();
    const body = filler(500);
    const created = await send(await signedCreate({ issuer, body, nowMs, headers: { [SOCKET_ADDRESS_HEADER]: "6.6.6.6" } }));
    expect(created.status).toBe(201);
    const { id } = (await created.json()) as { id: string };
    const read = await send(new Request(`${AUDIENCE}/v1/links/${id}`));
    expect(read.status).toBe(200);
    expect(new Uint8Array(await read.arrayBuffer())).toEqual(body);
    expect(read.headers.get("x-link-record")).toBeTruthy();
    expect((await send(await signedDelete({ issuer, id, nowMs }))).status).toBe(204);
    expect((await send(new Request(`${AUDIENCE}/v1/links/${id}`))).status).toBe(404);
  });

  it("the timer's tick sweeps and emits one health line without limits", async () => {
    await host.tick();
    const health = JSON.parse(lines.at(-1) ?? "{}");
    expect(health.event).toBe("links.health");
    expect(health.usage.requests.limit).toBeNull();
    expect(health.creates.share).toBeGreaterThanOrEqual(0);
  });
});
