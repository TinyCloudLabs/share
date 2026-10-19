import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { once } from "node:events";
import { createServer } from "node:http";
import { resolve } from "node:path";
import test from "node:test";
import { promisify } from "node:util";

const transport = resolve(import.meta.dirname, "cli-transport.mjs");

// Runs a probe in a child preloaded exactly as joined-gate.mjs preloads the CLI.
// Asynchronous so a loopback server in this process can still answer it.
async function probe(source, routes = {}) {
  const { stdout } = await promisify(execFile)(process.execPath, ["--import", transport, "--input-type=module", "-e", source], {
    env: { ...process.env, TC500_CLI_ROUTES: JSON.stringify(routes) },
    timeout: 20_000,
  });
  return JSON.parse(stdout.trim().split("\n").at(-1));
}

test("the CLI transport refuses IP-literal and hostname destinations outside the stack on every client path", async () => {
  const result = await probe(`
    import http from "node:http"; import https from "node:https"; import net from "node:net";
    const outcome = (start) => new Promise((done) => {
      const handle = start();
      handle.once("error", (error) => done(error.code ?? error.name));
      handle.once("connect", () => { handle.destroy(); done("connected"); });
      handle.once("response", () => done("connected"));
    });
    console.log(JSON.stringify({
      // RFC 5737 documentation addresses: never real hosts, even if a guard regressed.
      rawSocket: await outcome(() => net.connect(443, "192.0.2.1")),
      rawSocketOptions: await outcome(() => net.connect({ host: "198.51.100.1", port: 53 })),
      httpsIpLiteral: await outcome(() => https.get("https://203.0.113.1/")),
      httpHostname: await outcome(() => http.get("http://outside-the-stack.example/")),
      fetchIpLiteral: await fetch("http://192.0.2.1/").then(() => "connected", (error) => error.name),
      fetchUnmappedOrigin: await fetch("https://api.openkey.so/").then(() => "connected", (error) => error.name),
    }));
  `);
  assert.deepEqual(result, {
    rawSocket: "ECONNREFUSED",
    rawSocketOptions: "ECONNREFUSED",
    httpsIpLiteral: "ECONNREFUSED",
    httpHostname: "ECONNREFUSED",
    fetchIpLiteral: "TypeError",
    fetchUnmappedOrigin: "TypeError",
  });
});

test("the CLI transport delivers a mapped canonical origin to its loopback service", async () => {
  const server = createServer((request, response) => response.end(`${request.method} ${request.url}`)).listen(0, "127.0.0.1");
  await once(server, "listening");
  try {
    const result = await probe(
      `console.log(JSON.stringify({ body: await (await fetch("https://tee.node.tinycloud.xyz/info?probe=1")).text() }));`,
      { "https://tee.node.tinycloud.xyz": `http://127.0.0.1:${server.address().port}` },
    );
    assert.deepEqual(result, { body: "GET /info?probe=1" });
  } finally {
    server.close();
  }
});
