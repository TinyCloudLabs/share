/** Library renewal discovery keeps SDK admission separate from saved account lookup. Details: TC-2872 */
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { NodeWasmBindings, PrivateKeySigner } from "@tinycloud/node-sdk";
import { privateKeyToAccount } from "viem/accounts";
import { BrowserSessionStorage } from "@tinycloud/web-sdk";
import { LIBRARY_SESSION_PREFIX, saveLibraryAccount, savedLibraryAccount, savedLibraryRenewalAccount } from "../src/share/library-session.js";

const syntheticKey = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const address = privateKeyToAccount(syntheticKey).address;
const account = { address, keyId: "synthetic", keyType: "MANAGED" as const };
beforeEach(() => localStorage.clear());
afterEach(() => { vi.useRealTimers(); localStorage.clear(); });

async function save(prefix = LIBRARY_SESSION_PREFIX) {
  const sessions = new BrowserSessionStorage({ storage: localStorage, keyPrefix: prefix });
  const wasm = new NodeWasmBindings();
  const manager = wasm.createSessionManager();
  const keyId = manager.createSessionKey("library-candidate");
  const savedKey = manager.jwk(keyId);
  if (savedKey === undefined) throw new Error("missing synthetic session key");
  const jwk = JSON.parse(savedKey);
  const now = Date.now();
  const expiresAt = new Date(now + 60_000).toISOString();
  const prepared = wasm.prepareSession({
    address, chainId: 1, domain: "share.tinycloud.xyz", issuedAt: new Date(now).toISOString(), expirationTime: expiresAt,
    spaceId: wasm.makeSpaceId(address, 1, "applications"), jwk,
    abilities: { kv: { "xyz.tinycloud.share/": ["tinycloud.kv/get"] } },
  });
  const signature = await new PrivateKeySigner(syntheticKey).signMessage(prepared.siwe);
  const signed = wasm.completeSessionSetup({ ...prepared, signature });
  await sessions.save(address, {
    address, chainId: 1, sessionKey: JSON.stringify(jwk), siwe: prepared.siwe, signature,
    tinycloudSession: { delegationHeader: signed.delegationHeader, delegationCid: signed.delegationCid, spaceId: signed.spaceId, verificationMethod: manager.getDID(keyId) },
    expiresAt, createdAt: new Date(now).toISOString(), version: "1",
  });
  saveLibraryAccount(account);
  vi.useFakeTimers({ toFake: ["Date"], now: Date.now() + 61_000 });
  return sessions;
}

it("offers an expired record only as a renewal candidate and preserves ordinary expiration", async () => {
  const sessions = await save();
  expect(savedLibraryAccount()).toBeUndefined();
  expect(await savedLibraryRenewalAccount("explicit-input")).toEqual(account);
  expect((await sessions.loadRenewalCandidate(address)).status).toBe("renewal-candidate");
  expect(await savedLibraryRenewalAccount("")).toBeUndefined();
  expect((await sessions.loadWithStatus(address)).status).toBe("expired");
  expect(await savedLibraryRenewalAccount("explicit-input")).toBeUndefined();
});

it("keeps other Share prefixes separate", async () => {
  await save("tinycloud-share-runner-");
  expect(await savedLibraryRenewalAccount("explicit-input")).toBeUndefined();
});

it("requires the saved account to match the SDK candidate", async () => {
  await save();
  saveLibraryAccount({ ...account, address: "0x2234567890abcdef1234567890abcdef12345678" });
  expect(await savedLibraryRenewalAccount("explicit-input")).toBeUndefined();
});

it("refuses corrupt records and signed-out sessions", async () => {
  const sessions = await save();
  const saved = await sessions.loadRenewalCandidate(address);
  if (saved.data === null) throw new Error("missing synthetic candidate");
  sessions.markSignedOut(address, saved.data.signature);
  expect(await savedLibraryRenewalAccount("explicit-input")).toBeUndefined();
  localStorage.setItem(`${LIBRARY_SESSION_PREFIX}${address}`, "{}");
  expect(await savedLibraryRenewalAccount("explicit-input")).toBeUndefined();
});
