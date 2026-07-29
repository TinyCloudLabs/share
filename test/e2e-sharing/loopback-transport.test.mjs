import assert from "node:assert/strict";
import test from "node:test";
import { assertRoutingShimInstalled, loopbackTransportAbortPatterns } from "./loopback-transport.mjs";

const canonical = Object.freeze({
  share: "https://share.tinycloud.xyz",
  node: "https://node.tinycloud.xyz",
  credentials: "https://witness.credentials.org",
  registry: "https://registry.tinycloud.xyz",
});

test("loopbackTransportAbortPatterns covers every canonical origin the harness replaces", () => {
  assert.deepEqual(loopbackTransportAbortPatterns(canonical), [
    "https://node.tinycloud.xyz/**",
    "https://registry.tinycloud.xyz/**",
    "https://share.tinycloud.xyz/**",
    "https://witness.credentials.org/**",
  ]);
});

test("loopbackTransportAbortPatterns rejects a loopback, relative, or non-canonical origin", () => {
  assert.throws(() => loopbackTransportAbortPatterns({ node: "http://127.0.0.1:8080" }), /canonical HTTPS origin/);
  assert.throws(() => loopbackTransportAbortPatterns({ node: "https://127.0.0.1" }), /must not be loopback/);
  assert.throws(() => loopbackTransportAbortPatterns({ node: "https://node.tinycloud.xyz/info" }), /canonical HTTPS origin/);
  assert.throws(() => loopbackTransportAbortPatterns({ node: "node.tinycloud.xyz" }), /not a URL/);
  assert.throws(() => loopbackTransportAbortPatterns({ node: undefined }), /origin is missing/);
  assert.throws(() => loopbackTransportAbortPatterns({}), /at least one canonical origin/);
  assert.throws(() => loopbackTransportAbortPatterns([]), /canonical origin map/);
});

test("assertRoutingShimInstalled accepts the agent-browser string and boolean shapes", () => {
  assert.equal(assertRoutingShimInstalled("true", "/share.html"), true);
  assert.equal(assertRoutingShimInstalled(true, "/share.html"), true);
});

test("assertRoutingShimInstalled names the navigation that dropped the shim", () => {
  assert.throws(() => assertRoutingShimInstalled("false", "http://127.0.0.1:4321/share.html"), /http:\/\/127\.0\.0\.1:4321\/share\.html/);
  assert.throws(() => assertRoutingShimInstalled(undefined, "/viewer"), /loopback routing shim is absent/);
  assert.throws(() => assertRoutingShimInstalled("undefined", "/viewer"), /node\.tinycloud\.xyz/);
});
