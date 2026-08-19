import assert from "node:assert/strict";
import test from "node:test";
import { assertNodeShareV2Capability } from "./node-capability.mjs";

test("reads the sharing enforcer identity from the Node /info capability", () => {
  const capability = assertNodeShareV2Capability({
    shareV2: {
      id: "tinycloud.node-sharing-v2",
      version: 2,
      enforcerDid: "did:key:z6MkEnforcer",
    },
  });

  assert.equal(capability.enforcerDid, "did:key:z6MkEnforcer");
});

test("rejects missing, wrong-version, or malformed sharing capabilities", () => {
  assert.throws(() => assertNodeShareV2Capability({}), /omitted its sharing-v2 capability/);
  assert.throws(
    () => assertNodeShareV2Capability({ shareV2: { id: "tinycloud.node-sharing-v2", version: 1, enforcerDid: "did:key:z6MkEnforcer" } }),
    /omitted its sharing-v2 capability/,
  );
  assert.throws(
    () => assertNodeShareV2Capability({ shareV2: { id: "tinycloud.node-sharing-v2", version: 2, enforcerDid: "did:web:node.example" } }),
    /omitted its Ed25519 enforcer DID/,
  );
});
