import { describe, expect, it } from "vitest";

import * as sender from "./index.js";
import type { PreparedInvitationInputs } from "./invitation-input.js";

type SenderApi = typeof import("./index.js");

// These expected errors keep the production barrel from regrowing raw network
// clients or an explicitly forgeable prepared-input type.
// @ts-expect-error raw node transport is intentionally not a sender-barrel export
type RawNodeTransport = SenderApi["requestNodeAuthorization"];
// @ts-expect-error raw invitation transport is intentionally not a sender-barrel export
type RawInvitationTransport = SenderApi["requestInvitation"];
// @ts-expect-error prepared inputs are intentionally not a named sender-barrel export
type BarrelPreparedInputs = SenderApi["PreparedInvitationInputs"];

describe("sender API surface", () => {
  it("does not expose raw transport clients or prepared-input type names", () => {
    expect("requestNodeAuthorization" in sender).toBe(false);
    expect("requestInvitation" in sender).toBe(false);
    expect("PreparedInvitationInputs" in sender).toBe(false);
  });

  it("requires the module-private prepared brand for object literals", () => {
    // @ts-expect-error the module-private brand cannot be supplied by a caller
    const forged: PreparedInvitationInputs = {};
    expect(forged).toEqual({});
  });
});
