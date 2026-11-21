/**
 * The cancel mapping through OpenKey's own classifier: a real `ObservedOpenKeyProvider` is asked to sign, OpenKey rejects
 * the way it does, and `takeWalletApprovalFailure` (not a stand-in) says what the failure was.
 */
import { describe, expect, it, vi } from "vitest";
import { ObservedOpenKeyProvider, registerWalletApprovalObserver, type ShareTinyCloud } from "../src/share/openkey-session.js";
import { requestInOpenKey } from "../src/share/permission-step-up.js";

const ADDRESS = "0x1234567890abcdef1234567890abcdef12345678";
const PERMISSIONS = [{ service: "tinycloud.encryption", path: "urn:tinycloud:encryption:x:default", actions: ["decrypt"], skipPrefix: true }];
const MESSAGE_HEX = `0x${Buffer.from("sign in").toString("hex")}`;

/** A client whose permission request needs one signature from OpenKey, which rejects with `rejection`. */
function clientRejecting(rejection: unknown): ShareTinyCloud {
  const openkey = { signMessage: vi.fn(async () => { throw rejection; }) };
  const provider = new ObservedOpenKeyProvider(openkey as never, { address: ADDRESS, keyId: "key", keyType: "MANAGED" } as never, ADDRESS);
  const tinycloud = {
    hasPermissions: vi.fn(() => false),
    requestPermissions: vi.fn(async () => { await provider.request({ method: "personal_sign", params: [MESSAGE_HEX, ADDRESS] }); return { approved: true }; }),
  } as unknown as ShareTinyCloud;
  registerWalletApprovalObserver(tinycloud, provider);
  return tinycloud;
}

describe("requestInOpenKey with OpenKey's own failure classification", () => {
  it("USER_CANCELLED is a no", async () => {
    await expect(requestInOpenKey(clientRejecting({ code: "USER_CANCELLED", message: "cancelled" }), PERMISSIONS)).resolves.toBe(false);
  });

  it("the wallet's 4001 refusal is a no", async () => {
    await expect(requestInOpenKey(clientRejecting({ code: 4001 }), PERMISSIONS)).resolves.toBe(false);
  });

  it("a timeout is an error, not a no", async () => {
    await expect(requestInOpenKey(clientRejecting({ code: "TIMEOUT" }), PERMISSIONS)).rejects.toMatchObject({ code: "TIMEOUT" });
  });

  it("a failure OpenKey does not classify is an error, not a no", async () => {
    await expect(requestInOpenKey(clientRejecting(new Error("network down")), PERMISSIONS)).rejects.toThrow("network down");
  });
});
