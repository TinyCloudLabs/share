import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createServer } from "node:net";
import { afterEach, describe, it } from "node:test";
import { sandboxedCommand } from "./cli-joined.ts";

const servers = [];

afterEach(async () => {
  for (const server of servers.splice(0)) {
    if (server.listening) await new Promise((resolveClose) => server.close(() => resolveClose()));
  }
});

function run(command, args) {
  return new Promise((resolveRun, rejectRun) => {
    const child = spawn(command, args, { stdio: ["ignore", "ignore", "pipe"] });
    child.once("error", rejectRun);
    child.once("exit", (code) => resolveRun(code ?? 1));
  });
}

describe("joined process spawn boundary", () => {
  it("denies native public sockets and permits only the explicitly allocated loopback port", async () => {
    const denied = await sandboxedCommand(process.execPath, ["-e", "const net=require('node:net'); const socket=net.createConnection({host:'192.0.2.1',port:9}); socket.once('connect',()=>process.exit(1)); socket.once('error',()=>process.exit(0)); setTimeout(()=>process.exit(3),1000);"], []);
    assert.equal(await run(denied.command, denied.args), 0);

    const server = createServer((socket) => socket.end());
    servers.push(server);
    await new Promise((resolveListen, rejectListen) => {
      server.once("error", rejectListen);
      server.listen(0, "127.0.0.1", resolveListen);
    });
    const address = server.address();
    if (address === null || typeof address === "string") throw new Error("loopback test server did not bind");
    const allowed = await sandboxedCommand(process.execPath, ["-e", `const net=require('node:net'); const socket=net.createConnection({host:'127.0.0.1',port:${address.port}}); socket.once('connect',()=>process.exit(0)); socket.once('error',()=>process.exit(1)); setTimeout(()=>process.exit(2),1000);`], [address.port]);
    assert.equal(await run(allowed.command, allowed.args), 0);
    assert.match(allowed.args.join(" "), new RegExp(`remote tcp \\"localhost:${address.port}\\"`));
  });

  it("requires every child launch to provide an explicit loopback allow-list", async () => {
    const source = await (await import("node:fs/promises")).readFile(new URL("./cli-joined.ts", import.meta.url), "utf8");
    assert.match(source, /options: ChildOptions/);
    assert.doesNotMatch(source, /options: ChildOptions = \{\}/);
    assert.match(source, /const launched = await sandboxedCommand\(command, args, options\.allowLoopbackPorts\);/);
  });
});
