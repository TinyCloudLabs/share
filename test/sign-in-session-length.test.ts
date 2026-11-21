import { describe, expect, it, vi } from "vitest";

// An SDK whose own sign-in session default is not 30 days.
const SEVEN_DAYS = 7 * 24 * 60 * 60 * 1000;
vi.mock("@tinycloud/sdk-core", () => ({
  EXPIRY: { SESSION_MS: 7 * 24 * 60 * 60 * 1000 },
  authorizationVerdictOf: () => undefined,
  verifyEip191MessageSignature: async () => true,
  revokePolicyRootV3: async () => ({}),
}));

import { MAX_SESSION_MS, SIGN_IN_SESSION_MS } from "../src/share/openkey-session.js";

describe("the library's sign-in session length", () => {
  it("is 30 days whatever the SDK's own default is", () => {
    expect(SIGN_IN_SESSION_MS).toBe(30 * 24 * 60 * 60 * 1000);
    expect(SIGN_IN_SESSION_MS).not.toBe(SEVEN_DAYS);
    expect(SIGN_IN_SESSION_MS).toBeGreaterThan(MAX_SESSION_MS);
  });
});
