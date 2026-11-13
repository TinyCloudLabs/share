/** Library renewal discovery keeps SDK admission separate from saved account lookup. Details: TC-2872 */
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { BrowserSessionStorage } from "@tinycloud/web-sdk";
import { LIBRARY_SESSION_PREFIX, saveLibraryAccount, savedLibraryAccount, savedLibraryRenewalAccount } from "../src/share/library-session.js";

const address = "0x1234567890abcdef1234567890abcdef12345678";
const account = { address, keyId: "synthetic", keyType: "MANAGED" as const };
beforeEach(() => localStorage.clear());
afterEach(() => { vi.useRealTimers(); localStorage.clear(); });

async function save(prefix = LIBRARY_SESSION_PREFIX) {
  const sessions = new BrowserSessionStorage({ storage: localStorage, keyPrefix: prefix });
  await sessions.save(address, {
    address, chainId: 1, sessionKey: JSON.stringify({ kty: "OKP", crv: "Ed25519", x: "x" }),
    siwe: "synthetic", signature: "0xsynthetic",
    tinycloudSession: { delegationHeader: { Authorization: "Bearer synthetic" }, delegationCid: "bafy", spaceId: "space", verificationMethod: "did:key:z" },
    expiresAt: new Date(Date.now() + 1_000).toISOString(), createdAt: new Date(Date.now() - 2_000).toISOString(), version: "1",
  });
  saveLibraryAccount(account);
  vi.useFakeTimers({ toFake: ["Date"], now: Date.now() + 2_000 });
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
  sessions.markSignedOut(address, "0xsynthetic");
  expect(await savedLibraryRenewalAccount("explicit-input")).toBeUndefined();
  localStorage.setItem(`${LIBRARY_SESSION_PREFIX}${address}`, "{}");
  expect(await savedLibraryRenewalAccount("explicit-input")).toBeUndefined();
});
