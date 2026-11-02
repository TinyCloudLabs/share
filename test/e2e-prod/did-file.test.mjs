import { test } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { didFileTarget, didFromSiwe, writeDidFile } from "./did-file.mjs";

const OWNER = { did: "did:pkh:eip155:1:0x00000000000000000000000000000000000000A1", email: "qa-courier-smoke-000000000000@example.test" };

test("the DID file is off by default", () => {
  assert.equal(didFileTarget({}), undefined);
  assert.equal(didFileTarget({ COURIER_SMOKE_DID_FILE: "" }), undefined);
});

test("the DID file must be a plain absolute path under /var/tmp", () => {
  for (const path of ["/tmp/dids.txt", "dids.txt", "/var/tmp/../etc/dids.txt", "/var/tmpx/dids.txt", "/home/dids.txt"]) {
    assert.throws(() => didFileTarget({ COURIER_SMOKE_DID_FILE: path }), /under \/var\/tmp/, path);
  }
  const directory = mkdtempSync("/var/tmp/did-file-test-");
  try {
    assert.equal(didFileTarget({ COURIER_SMOKE_DID_FILE: join(directory, "dids.txt") }), join(directory, "dids.txt"));
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("the DID file is created 0600 with one owner per line and nothing else", () => {
  const directory = mkdtempSync("/var/tmp/did-file-test-");
  try {
    const path = join(directory, "dids.txt");
    assert.equal(writeDidFile(path, [OWNER, { did: undefined, email: "x@example.test" }]), 1);
    assert.equal(statSync(path).mode & 0o777, 0o600);
    assert.equal(readFileSync(path, "utf8"), `${OWNER.did} ${OWNER.email}\n`);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("an existing DID file with looser permissions, or a symlink, is refused and left alone", () => {
  const directory = mkdtempSync("/var/tmp/did-file-test-");
  try {
    const loose = join(directory, "loose.txt");
    writeFileSync(loose, "before\n");
    chmodSync(loose, 0o644);
    assert.throws(() => writeDidFile(loose, [OWNER]), /0600/);
    assert.equal(readFileSync(loose, "utf8"), "before\n");
    const target = join(directory, "target.txt");
    writeFileSync(target, "", { mode: 0o600 });
    const link = join(directory, "link.txt");
    symlinkSync(target, link);
    assert.throws(() => writeDidFile(link, [OWNER]));
    assert.equal(readFileSync(target, "utf8"), "");
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
  assert.equal(existsSync(directory), false);
});

test("the owner DID is read from a signed SIWE message", () => {
  const siwe = `share.tinycloud.xyz wants you to sign in with your Ethereum account:\n0x00000000000000000000000000000000000000A1\n\nURI: did:key:z6Mk\nVersion: 1\nChain ID: 1\nNonce: n`;
  assert.equal(didFromSiwe(siwe), OWNER.did);
  assert.equal(didFromSiwe("no address here"), undefined);
});
