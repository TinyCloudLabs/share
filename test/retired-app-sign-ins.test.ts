// @vitest-environment jsdom
import { beforeEach, describe, expect, it } from "vitest";
import { clearRetiredAppSignIns } from "../src/share/retired-app-sign-ins.js";
import { LIBRARY_SESSION_PREFIX } from "../src/share/library-session.js";

const APP = "tinycloud-share-runner-0a1b2c3d4e5f60718293a4b5c6d7e8f9";
const ADDRESS = "0x70997970c51812dc3a010c7d01b50e0d17dc79c8";

beforeEach(() => {
  window.localStorage.clear();
  window.sessionStorage.clear();
});

describe("retired app sign-ins", () => {
  it("removes every record the app runner kept for an app, and nothing the library or Courier keeps", () => {
    for (const key of [`${APP}${ADDRESS}`, `${APP}renewal-receipt`, `${APP}-runtime-grants`, `${APP}active-address`, `tinycloud-share-runner-ffffffffffffffffffffffffffffffff${ADDRESS}`]) {
      window.localStorage.setItem(key, "{}");
    }
    const kept = [`${LIBRARY_SESSION_PREFIX}${ADDRESS}`, `${LIBRARY_SESSION_PREFIX}renewal-receipt`, `tinycloud-courier${ADDRESS}`, "tinycloud-share", `tinycloud-share${ADDRESS}`, "unrelated"];
    for (const key of kept) window.localStorage.setItem(key, "kept");
    clearRetiredAppSignIns();
    expect(Object.keys({ ...window.localStorage }).sort()).toEqual([...kept].sort());
  });

  it("leaves sessionStorage alone and is idempotent", () => {
    window.sessionStorage.setItem(`${APP}${ADDRESS}`, "kept");
    clearRetiredAppSignIns();
    clearRetiredAppSignIns();
    expect(window.sessionStorage.getItem(`${APP}${ADDRESS}`)).toBe("kept");
  });

  it("tolerates blocked storage", () => {
    expect(() => clearRetiredAppSignIns(() => { throw new DOMException("The operation is insecure.", "SecurityError"); })).not.toThrow();
    expect(() => clearRetiredAppSignIns(() => ({ length: 1, key: () => `${APP}${ADDRESS}`, removeItem: () => { throw new DOMException("denied", "SecurityError"); } }))).not.toThrow();
  });
});
