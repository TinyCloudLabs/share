// @vitest-environment jsdom
import { beforeEach, describe, expect, it, vi } from "vitest";
import { endSenderSession, SIGNED_OUT_NOTICE, SIGNED_OUT_PARTIAL_NOTICE } from "../src/share/sender-chrome.js";
import { LIBRARY_SESSION_PREFIX } from "../src/share/library-session.js";
import { saveRenewalReceipt } from "../src/share/renewal-store.js";
import type { OpenKeyShareSession, ShareTinyCloud } from "../src/share/openkey-session.js";

const ADDRESS = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";
const LEASE = { version: 1, approvedAt: "2026-11-21T12:00:00.000Z", receipt: { leaseExpiresAt: "2999-01-01T00:00:00.000Z" } };

// A tab restored through the lease: nothing here signed in with OpenKey, but it holds the
// client `reopenOpenKey` gave it and the receipt of a running lease.
const resumedTab = (signOut: () => Promise<{ requestId: string; revoked: boolean }>, signOutTinyCloud = vi.fn(async () => undefined)) => ({
  session: { address: ADDRESS, openkey: { signOut, disconnect: vi.fn() } } as unknown as OpenKeyShareSession,
  tinycloud: { signOut: signOutTinyCloud } as unknown as ShareTinyCloud,
});

beforeEach(() => {
  localStorage.clear();
  sessionStorage.clear();
  saveRenewalReceipt(LIBRARY_SESSION_PREFIX, ADDRESS, LEASE);
});

describe("Sign out in a tab restored through the lease", () => {
  it("asks OpenKey to sign out, so the lease stops, and says so once OpenKey confirms", async () => {
    const signOut = vi.fn(async () => ({ requestId: "r", revoked: true }));
    const tab = resumedTab(signOut);

    expect(await endSenderSession(tab)).toBe("openkey-ended");
    expect(signOut).toHaveBeenCalledTimes(1);
    expect(tab.tinycloud.signOut).toHaveBeenCalledTimes(1);
    expect(SIGNED_OUT_NOTICE).toBe("Signed out of Share in this browser. Share's access won't renew.");
  });

  it("gives the partial notice, not the confirmed one, when OpenKey does not confirm", async () => {
    const signOut = vi.fn(async () => ({ requestId: "r", revoked: false }));

    expect(await endSenderSession(resumedTab(signOut))).toBe("openkey-unconfirmed");
    expect(signOut).toHaveBeenCalledTimes(1);
    expect(SIGNED_OUT_PARTIAL_NOTICE).toBe("You're signed out of Share in this browser, but OpenKey may still be renewing its access. To stop that, choose Stop renewal under Renewing permissions in OpenKey settings.");
  });

  it("still ends Share's own session when OpenKey cannot be reached", async () => {
    const tab = resumedTab(async () => { throw { code: "POPUP_BLOCKED" }; });

    expect(await endSenderSession(tab)).toBe("openkey-unconfirmed");
    expect(tab.tinycloud.signOut).toHaveBeenCalledTimes(1);
  });
});
