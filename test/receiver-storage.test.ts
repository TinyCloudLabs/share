// @vitest-environment jsdom
import { beforeEach, describe, expect, it } from "vitest";
import { purgeLegacyReceiverStorage } from "../src/email-share/receiver-storage.js";

beforeEach(() => {
  window.sessionStorage.clear();
});

describe("legacy receiver records", () => {
  it("removes a legacy key record and the credentials issued to it, and nothing else", () => {
    window.sessionStorage.setItem("tinycloud.share.receiver-session.v1", "{}");
    window.sessionStorage.setItem("tinycloud.share.receiver-credentials.v1", "{}");
    window.sessionStorage.setItem("unrelated", "kept");
    purgeLegacyReceiverStorage();
    expect(Object.keys({ ...window.sessionStorage })).toEqual(["unrelated"]);
  });

  it("keeps credentials that belong to the current non-extractable key", () => {
    window.sessionStorage.setItem("tinycloud.share.receiver-credentials.v1", "{}");
    purgeLegacyReceiverStorage();
    expect(window.sessionStorage.getItem("tinycloud.share.receiver-credentials.v1")).toBe("{}");
  });

  it("tolerates blocked storage", () => {
    expect(() => purgeLegacyReceiverStorage(() => { throw new DOMException("The operation is insecure.", "SecurityError"); })).not.toThrow();
    expect(() => purgeLegacyReceiverStorage(() => ({ getItem: () => "{}", removeItem: () => { throw new DOMException("denied", "SecurityError"); } }))).not.toThrow();
  });
});
